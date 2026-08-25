# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The console: what it refuses, and what it must never rewrite.

This module is the one place in the app that runs a command it did not
assemble itself, so its tests are mostly about what it does NOT do. It does not
filter, because a blocklist that stops `rm -rf /` and not `dd` would imply a
safety that is not there. It does not rewrite the command, because running
something other than what was typed is the single failure this feature cannot
have. And it does not open a shell to Python — `subprocess` still gets a list.

What it refuses is only the input that is not a command at all.
"""

import unittest

from server.bench import console


class TestRefusals(unittest.TestCase):
	def test_an_empty_command_is_refused(self):
		with self.assertRaises(console.Refusal):
			console.validate("")

	def test_whitespace_only_is_refused(self):
		"""Otherwise `bash -lc "   "` runs, succeeds, and produces nothing.

		A job that reports Success for a command nobody typed is worse than an
		error message.
		"""
		with self.assertRaises(console.Refusal):
			console.validate("   \n\t ")

	def test_none_is_refused_rather_than_crashing(self):
		with self.assertRaises(console.Refusal):
			console.validate(None)

	def test_an_over_length_command_is_refused_with_both_numbers(self):
		"""The message has to say how long it was AND what the limit is.

		"Too long" leaves the operator trimming blindly.
		"""
		with self.assertRaises(console.Refusal) as caught:
			console.validate("x" * (console.MAX_COMMAND + 1))
		message = str(caught.exception)
		self.assertIn(str(console.MAX_COMMAND + 1), message)
		self.assertIn(str(console.MAX_COMMAND), message)

	def test_a_command_at_exactly_the_limit_is_allowed(self):
		self.assertEqual(len(console.validate("x" * console.MAX_COMMAND)), console.MAX_COMMAND)

	def test_a_null_byte_is_refused(self):
		"""A NUL truncates the command at execve, silently.

		Everything after it would be dropped, so the shell would run a PREFIX
		of what was asked for — which is the one outcome this module must never
		produce.
		"""
		with self.assertRaises(console.Refusal):
			console.validate("echo hello\x00 && rm -rf /tmp/x")

	def test_surrounding_whitespace_is_stripped(self):
		self.assertEqual(console.validate("  ls -la  "), "ls -la")


class TestTheCommandIsNeverRewritten(unittest.TestCase):
	"""Whatever was typed is what runs. Anything else is a silent substitution."""

	def test_argv_is_three_elements_with_the_command_last(self):
		argv = console.build_argv("ls -la")
		self.assertEqual(len(argv), 3)
		self.assertEqual(argv[-1], "ls -la")

	def test_a_pipeline_survives_intact(self):
		"""Pipes are most of the reason to want a shell rather than an argv."""
		command = "ps aux | grep -i frappe | head -5"
		self.assertEqual(console.build_argv(command)[-1], command)

	def test_and_and_redirection_survive_intact(self):
		command = "cd apps && git status --porcelain > /tmp/out 2>&1"
		self.assertEqual(console.build_argv(command)[-1], command)

	def test_quotes_and_globs_survive_intact(self):
		command = """find . -name '*.py' -newer setup.py -exec grep -l "def test" {} +"""
		self.assertEqual(console.build_argv(command)[-1], command)

	def test_a_login_shell_is_used(self):
		"""Without -l, `bench` is not on PATH under a worker.

		The first command anyone tries is usually a bench command, and it would
		fail in a way that reads as the feature being broken rather than as an
		environment difference.
		"""
		argv = console.build_argv("bench version")
		self.assertEqual(argv[0], console.SHELL)
		self.assertIn("l", argv[1])


class TestNoShellTrueAnywhere(unittest.TestCase):
	"""Bash interprets the string; Python must not.

	Handing the command to bash is deliberate. Handing it to `subprocess` with
	`shell=True` as well would be a second, invisible layer of interpretation
	over a string that has already been interpreted once — which is how a
	command containing a quote runs as something else entirely.
	"""

	def test_no_call_in_the_module_passes_shell(self):
		"""Checked on the parsed source, not by searching the text.

		The first version of this test grepped for "shell=True" and failed on
		the module's own docstring, which explains at length why it is not
		used. Reading the AST asks the question that actually matters: does any
		CALL pass that keyword.
		"""
		import ast
		import inspect

		tree = ast.parse(inspect.getsource(console))
		offenders = [
			node.lineno
			for node in ast.walk(tree)
			if isinstance(node, ast.Call)
			for keyword in node.keywords
			if keyword.arg == "shell"
		]
		self.assertEqual(offenders, [])

	def test_build_argv_returns_a_list_not_a_string(self):
		"""Popen treats a string as a program name, not a command line."""
		self.assertIsInstance(console.build_argv("ls"), list)


class TestSummarise(unittest.TestCase):
	"""`app_name` is the label in the dock, so it comes from the command."""

	def test_a_short_command_is_used_whole(self):
		self.assertEqual(console.summarise("git status"), "git status")

	def test_a_long_command_is_truncated_with_an_ellipsis(self):
		summary = console.summarise("x" * 200, limit=30)
		self.assertEqual(len(summary), 30)
		self.assertTrue(summary.endswith("…"))

	def test_newlines_are_collapsed(self):
		"""A dock entry titled with a line break in the middle is unreadable."""
		self.assertEqual(console.summarise("cd apps\n  && ls"), "cd apps && ls")

	def test_an_empty_command_summarises_to_empty_rather_than_crashing(self):
		self.assertEqual(console.summarise(""), "")


class TestTheStepPlan(unittest.TestCase):
	def test_a_console_run_rescans_afterwards(self):
		"""Because the command was arbitrary, not despite it.

		The first version of this plan left the rescan out, reasoning that a
		console command might change nothing. Running it showed the flaw: the
		installer rescans after every job regardless, so the log said "Bench
		re-read from disk" with no step to account for it — and the reasoning
		was wrong anyway. A `git checkout` in an app directory moves a branch,
		and the app list would show the old one until somebody noticed.
		"""
		from server.bench import steps

		keys = [step.key for step in steps.for_console("ls -la")]
		self.assertEqual(keys, ["check", "run", "rescan"])

	def test_the_run_step_is_titled_with_the_command(self):
		from server.bench import steps

		plan = steps.for_console("git status --porcelain")
		self.assertEqual(plan[1].title, "git status --porcelain")
