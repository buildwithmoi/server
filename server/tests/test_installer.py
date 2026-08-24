# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Installer safety tests.

The subprocess behaviour matters more than anything else in this app: a bench
command that hangs takes an RQ worker with it and never gives it back. These
exercise the four anti-hang layers against real processes rather than mocks,
because the failure being guarded against is a real kernel-level one.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest

from server.bench import installer

ENV = {"PATH": "/usr/bin:/bin"}


class TestStreaming(unittest.TestCase):
	def test_stdout_and_stderr_are_interleaved(self):
		"""One readable log is worth more than two separable streams.

		This is exactly why exit_code, not log text, decides success.
		"""
		lines = []
		code, _timed_out = installer._stream(
			["bash", "-c", "echo one; echo problem >&2; echo two"],
			cwd="/tmp",
			env=ENV,
			timeout=30,
			on_line=lines.append,
		)
		self.assertEqual(code, 0)
		self.assertEqual(lines, ["one", "problem", "two"])

	def test_non_zero_exit_is_returned(self):
		code, _timed_out = installer._stream(
			["bash", "-c", "exit 42"], cwd="/tmp", env=ENV, timeout=30, on_line=lambda _: None
		)
		self.assertEqual(code, 42)


class TestCarriageReturnProgress(unittest.TestCase):
	"""git draws progress with \r, and it must reach the log as it happens.

	A text-mode pipe only yields on a newline, so a `git fetch` that runs for
	twenty minutes produced an EMPTY log until the instant it finished — which
	is indistinguishable from a hung job, and is exactly what a real erpnext
	pull looked like before this was fixed.
	"""

	def test_carriage_return_progress_streams_live(self):
		seen = []
		start = time.monotonic()
		code, _timed_out = installer._stream(
			[
				"bash",
				"-c",
				r"for i in 10 50 100; do printf 'Receiving objects: %d%%\r' $i; sleep 0.3; done; printf '\ndone\n'",
			],
			cwd="/tmp",
			env=ENV,
			timeout=30,
			on_line=lambda line: seen.append((time.monotonic() - start, line)),
		)
		self.assertEqual(code, 0)
		texts = [line for _, line in seen]
		self.assertIn("Receiving objects: 10%", texts)
		self.assertIn("Receiving objects: 100%", texts)
		self.assertIn("done", texts)
		self.assertLess(seen[0][0], 1.0, "first progress line must arrive while the command is still running")

	def test_progress_lines_are_separate_not_one_blob(self):
		seen = []
		installer._stream(
			["bash", "-c", r"printf 'a\rb\rc\n'"],
			cwd="/tmp",
			env=ENV,
			timeout=20,
			on_line=seen.append,
		)
		self.assertEqual(seen, ["a", "b", "c"])

	def test_newlines_still_work(self):
		seen = []
		installer._stream(
			["bash", "-c", "printf 'one\ntwo\n'"],
			cwd="/tmp",
			env=ENV,
			timeout=20,
			on_line=seen.append,
		)
		self.assertEqual(seen, ["one", "two"])

	def test_non_utf8_output_does_not_crash(self):
		seen = []
		code, _timed_out = installer._stream(
			["bash", "-c", r"printf 'ok \xff\xfe bytes\n'"],
			cwd="/tmp",
			env=ENV,
			timeout=20,
			on_line=seen.append,
		)
		self.assertEqual(code, 0)
		self.assertTrue(any("bytes" in line for line in seen))


class TestStdinIsClosed(unittest.TestCase):
	"""Layer 1: a command that asks for input must fail, not wait."""

	def test_interactive_read_returns_immediately(self):
		start = time.monotonic()
		installer._stream(
			["bash", "-c", "read -r answer; echo got=$answer"],
			cwd="/tmp",
			env=ENV,
			timeout=25,
			on_line=lambda _: None,
		)
		self.assertLess(time.monotonic() - start, 5, "a read on closed stdin must not block")

	def test_click_confirm_aborts_on_closed_stdin(self):
		"""The precise mechanism that saves us from bench's overwrite prompt.

		bench asks 'a directory already exists, overwrite?' via click.confirm,
		which catches EOFError and raises Abort — so with stdin closed the
		prompt becomes an immediate non-zero exit instead of a stuck worker.
		"""
		code = (
			"import click, sys\n"
			"try:\n"
			"    click.confirm('overwrite?')\n"
			"    sys.exit(0)\n"
			"except click.exceptions.Abort:\n"
			"    sys.exit(7)\n"
		)
		result = subprocess.run(
			[sys.executable, "-c", code], stdin=subprocess.DEVNULL, capture_output=True, timeout=25
		)
		self.assertEqual(result.returncode, 7, "click must abort rather than answer the prompt")


class TestWatchdog(unittest.TestCase):
	"""Layer 4: a command that goes SILENT must still be killed."""

	def _run_with_pgid(self, argv, timeout):
		captured = {}
		real_popen = subprocess.Popen

		def spy(*args, **kwargs):
			proc = real_popen(*args, **kwargs)
			captured["pgid"] = os.getpgid(proc.pid)
			return proc

		subprocess.Popen = spy
		try:
			lines = []
			started = time.monotonic()
			code, _timed_out = installer._stream(
				argv, cwd="/tmp", env=ENV, timeout=timeout, on_line=lines.append
			)
			return code, time.monotonic() - started, lines, captured.get("pgid")
		finally:
			subprocess.Popen = real_popen

	@staticmethod
	def _group_alive(pgid: int) -> bool:
		try:
			os.killpg(pgid, 0)
		except ProcessLookupError:
			return False
		except PermissionError:
			return True
		return True

	def test_silent_command_is_killed_at_the_deadline(self):
		"""The regression this file exists for.

		The first implementation checked the deadline inside `for line in
		proc.stdout`, which blocks until the next line — so a command that
		produced no output was never checked and ran forever. That is precisely
		the hang being defended against.
		"""
		code, elapsed, lines, _ = self._run_with_pgid(["bash", "-c", "echo start; sleep 240"], timeout=3)
		self.assertLess(elapsed, 30, "watchdog did not fire on a silent command")
		self.assertNotEqual(code, 0)
		self.assertTrue(any("timed out" in line for line in lines))

	def test_grandchildren_are_killed_too(self):
		"""bench spawns git and pip; killing only the wrapper orphans them."""
		_, _, _, pgid = self._run_with_pgid(["bash", "-c", "echo start; sleep 240 & wait"], timeout=3)
		self.assertIsNotNone(pgid)
		time.sleep(1.0)
		self.assertFalse(self._group_alive(pgid), "the whole process group must be gone")

	def test_fast_command_is_not_killed(self):
		lines = []
		code, _timed_out = installer._stream(
			["bash", "-c", "echo quick"], cwd="/tmp", env=ENV, timeout=30, on_line=lines.append
		)
		self.assertEqual(code, 0)
		self.assertNotIn("timed out", " ".join(lines))


class TestFailureExplanation(unittest.TestCase):
	"""A wrong diagnosis is worse than none — it sends people to fix the wrong thing."""

	class _Request:
		allow_merge = False

	def test_timeout_is_reported_as_a_timeout(self):
		"""The regression this exists for.

		A real erpnext pull was killed by the watchdog at thirty minutes, and
		the operator was told the branch had diverged — a different problem with
		a different fix. Both surface as exit -15.
		"""
		message = installer._explain_failure(-15, True, 1800, self._Request(), "git pull")
		self.assertIn("1800s", message)
		self.assertIn("Install Timeout", message, "must say how to give it longer")
		self.assertNotIn("diverged", message, "a timeout is not a divergence")

	def test_divergence_is_only_blamed_when_it_did_not_time_out(self):
		message = installer._explain_failure(1, False, 1800, self._Request(), "git pull")
		self.assertIn("diverged", message)
		self.assertIn("Allow Merge Commit", message)

	def test_a_signal_kill_is_not_called_a_divergence(self):
		message = installer._explain_failure(-9, False, 1800, self._Request(), "git pull")
		self.assertIn("signal 9", message)
		self.assertNotIn("diverged", message)

	def test_clone_failures_do_not_mention_merging(self):
		message = installer._explain_failure(1, False, 1800, self._Request(), "bench get-app")
		self.assertIn("bench get-app", message)
		self.assertNotIn("Allow Merge Commit", message)

	def test_timeout_mentions_shallow_clones(self):
		"""bench clones --depth 1, and pulling into a shallow repo is expensive.

		That is the actual reason the erpnext pull ran long, so it belongs in
		the message rather than in someone's memory.
		"""
		message = installer._explain_failure(-15, True, 1800, self._Request(), "git pull")
		self.assertIn("shallow", message.lower())


class TestNeverRanSentinel(unittest.TestCase):
	def test_sentinel_is_distinct_from_success(self):
		"""exit_code is NOT NULL, and 0 already means success.

		Writing None threw a MySQL column error from inside the failure handler,
		which then replaced the actionable pre-flight message with a database
		error — the operator was told about a constraint instead of the missing
		branch that actually stopped them.
		"""
		self.assertNotEqual(installer.NEVER_RAN, 0)
		self.assertLess(installer.NEVER_RAN, 0)


if __name__ == "__main__":
	unittest.main()
