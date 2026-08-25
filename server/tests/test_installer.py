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
		total = time.monotonic() - start
		self.assertEqual(code, 0)
		texts = [line for _, line in seen]
		self.assertIn("Receiving objects: 10%", texts)
		self.assertIn("Receiving objects: 100%", texts)
		self.assertIn("done", texts)

		# The property is that the lines arrived SPREAD OUT across the run
		# rather than all at once when the pipe closed. Asserted relative to the
		# run's own duration rather than against a wall-clock bound: the command
		# takes about 0.9s, so an absolute "under 1.0s" is only marginally under
		# its own runtime and fails on a loaded machine for reasons that have
		# nothing to do with buffering.
		spread = seen[-1][0] - seen[0][0]
		self.assertGreater(spread, 0.4, "progress arrived in one burst — the pipe is buffering")
		self.assertLess(
			seen[0][0], total * 0.7, "first progress line did not arrive while the command was running"
		)

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


class TestSupervisorPostStepIsNotAFailure(unittest.TestCase):
	"""bench exits 1 after a perfectly good clone, and that must not read as failure.

	bench ends `get-app` by calling `sudo supervisorctl status` to decide
	whether to restart processes. On a host with no passwordless sudo that
	raises and bench exits 1 — after the app has been cloned and pip-installed.
	It does this even when restart_supervisor_on_update is false. Two real
	erpnext clones were reported as failures this way, and a re-run needs
	--overwrite, which archives the app that was already fine.
	"""

	def test_the_post_step_is_recognised(self):
		log = (
			"Installing erpnext\n"
			'  File "/usr/local/lib/python3.12/dist-packages/bench/utils/bench.py", line 350, '
			"in restart_supervisor_processes\n"
			'    supervisor_status = get_cmd_output("sudo supervisorctl status", cwd=bench_path)\n'
			"subprocess.CalledProcessError: Command 'sudo supervisorctl status' returned non-zero exit status 1."
		)
		self.assertTrue(installer._SUPERVISOR_POSTSTEP.search(log))

	def test_an_unrelated_failure_is_not_mistaken_for_it(self):
		"""A genuine clone failure must still be a failure."""
		log = "fatal: could not read Username for 'https://github.com': No such device or address"
		self.assertIsNone(installer._SUPERVISOR_POSTSTEP.search(log))

	def test_outcome_check_requires_the_app_on_disk(self):
		"""The exit code answers a different question from 'is it installed'."""
		import tempfile

		class _Request:
			branch = None

			def __init__(self, path):
				self.app_path = path

		with tempfile.TemporaryDirectory() as tmp:
			self.assertFalse(
				installer._clone_landed(_Request(os.path.join(tmp, "nope"))),
				"a missing directory can never count as landed",
			)

	def test_outcome_check_rejects_the_wrong_branch(self):
		"""Landing something is not the same as landing what was asked for."""
		import subprocess as sp
		import tempfile

		with tempfile.TemporaryDirectory() as tmp:
			repo = os.path.join(tmp, "app")
			os.makedirs(repo)
			env = {
				"PATH": "/usr/bin:/bin",
				"HOME": tmp,
				"GIT_AUTHOR_NAME": "t",
				"GIT_AUTHOR_EMAIL": "t@t",
				"GIT_COMMITTER_NAME": "t",
				"GIT_COMMITTER_EMAIL": "t@t",
			}
			for argv in (
				["git", "init", "-q", "-b", "main"],
				["git", "remote", "add", "upstream", "https://example.invalid/a.git"],
				["git", "commit", "-q", "--allow-empty", "-m", "x"],
			):
				sp.run(argv, cwd=repo, env=env, check=True, capture_output=True)

			class _Request:
				app_path = repo
				branch = "main"

			self.assertTrue(installer._clone_landed(_Request()))

			class _Wrong(_Request):
				branch = "version-15"

			self.assertFalse(installer._clone_landed(_Wrong()))


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


try:
	import frappe as _frappe

	_HAS_SITE = bool(getattr(_frappe.local, "site", None))
except Exception:  # pragma: no cover
	_frappe = None
	_HAS_SITE = False


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestCancellationFromAThread(unittest.TestCase):
	"""The cancel check has to work from the POLLER THREAD, not just at all.

	It did not, and nothing noticed. `frappe.local` is backed by a ContextVar
	and a new thread starts with an empty context rather than a copy of its
	parent's, so `frappe.cache.get_value()` — which reads `frappe.local.conf`
	to namespace the key — raised AttributeError on the first tick. The bare
	`except` swallowed it, the thread returned, and every job was uncancellable
	for its whole life while the interface said "Stopping…".

	The fix is to namespace the key on the main thread and do a raw redis GET
	from the poller, so these tests build the closure exactly as
	`run_install_request` builds it.
	"""

	def setUp(self):
		self.raw_key = installer.CANCEL_KEY.format(name="AIR-TESTONLY")
		self.client = _frappe.cache
		self.key = self.client.make_key(self.raw_key)
		self.client.delete(self.key)

	def tearDown(self):
		self.client.delete(self.key)

	def _should_cancel(self):
		key, client = self.key, self.client
		return lambda: client.get(key) is not None

	def test_the_frappe_wrapper_still_cannot_be_used_from_a_thread(self):
		"""Guards the assumption the fix rests on.

		If a future frappe makes this work, the workaround is no longer needed
		— and if this test starts failing, that is what happened.
		"""
		import threading

		captured = {}

		def probe():
			try:
				captured["value"] = _frappe.cache.get_value(self.raw_key)
			except Exception as exc:  # noqa: BLE001
				captured["error"] = type(exc).__name__

		thread = threading.Thread(target=probe)
		thread.start()
		thread.join()
		self.assertIn("error", captured, "frappe.cache now works from a thread; simplify should_cancel")

	def test_a_precomputed_key_is_readable_from_a_thread(self):
		import threading

		self.client.set(self.key, b"1", ex=60)
		captured = {}
		check = self._should_cancel()

		thread = threading.Thread(target=lambda: captured.update(value=check()))
		thread.start()
		thread.join()
		self.assertTrue(captured.get("value"))

	def test_a_silent_command_is_actually_killed(self):
		"""The case the poller exists for: a job that produces no output cannot
		be interrupted by a check inside the read loop, because the loop is
		blocked on the pipe."""
		import threading
		import time as _time

		check = self._should_cancel()
		threading.Timer(1.0, lambda: self.client.set(self.key, b"1", ex=60)).start()

		lines = []
		started = _time.monotonic()
		code, timed_out = installer._stream(
			["sleep", "60"], "/tmp", ENV, 300, lines.append, check
		)
		elapsed = _time.monotonic() - started

		self.assertLess(elapsed, 15, "cancellation did not interrupt a silent command")
		self.assertNotEqual(code, 0)
		self.assertFalse(timed_out, "reported as a timeout rather than a cancellation")
		self.assertTrue(any("cancelled" in line for line in lines))

	def test_an_unset_flag_leaves_the_job_alone(self):
		check = self._should_cancel()
		code, _ = installer._stream(["echo", "fine"], "/tmp", ENV, 30, lambda _l: None, check)
		self.assertEqual(code, 0)

	def test_a_failing_check_does_not_disable_cancellation_for_the_job(self):
		"""Returning on the first failure is exactly how this went unnoticed."""
		calls = []

		def flaky():
			calls.append(1)
			if len(calls) < 3:
				raise RuntimeError("redis blip")
			return True

		lines = []
		code, _ = installer._stream(["sleep", "60"], "/tmp", ENV, 300, lines.append, flaky)
		self.assertNotEqual(code, 0, "the job survived a blip but was then never cancellable")
		self.assertGreaterEqual(len(calls), 3)
