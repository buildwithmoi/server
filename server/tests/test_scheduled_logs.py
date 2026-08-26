# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The two logs that record what nobody watched.

Neither needs a site: what is worth testing is the summarising, not frappe's
own list query.
"""

from __future__ import annotations

import unittest

from server.api import _last_exception_line
from server.bench import siteconfig


class LastExceptionLine(unittest.TestCase):
	"""A traceback identified by the line that says what went wrong."""

	TRACEBACK = """Traceback (most recent call last):
  File "/home/patoo/fb-16-server/apps/server/server/security/watch.py", line 88, in run_account_scan
    findings = accounts_rules.judge(snapshot)
  File "/home/patoo/fb-16-server/apps/server/server/security/accounts_rules.py", line 40, in judge
    for field in ACCOUNT_FIELDS:
NameError: name 'ACCOUNT_FIELDS' is not defined"""

	def test_the_exception_is_what_identifies_a_traceback(self):
		# Not the first line ("Traceback (most recent call last):"), which is
		# the same on every failure ever recorded and so identifies none.
		self.assertEqual(
			_last_exception_line(self.TRACEBACK),
			"NameError: name 'ACCOUNT_FIELDS' is not defined",
		)

	def test_a_frame_line_is_never_mistaken_for_the_exception(self):
		frames_only = '  File "x.py", line 1, in f\n    do_thing()\n'
		self.assertEqual(_last_exception_line(frames_only), "")

	def test_it_is_bounded(self):
		self.assertLessEqual(len(_last_exception_line("E: " + "x" * 5000)), 200)

	def test_nothing_in_is_nothing_out(self):
		for empty in ("", None, "   \n\n  "):
			self.assertEqual(_last_exception_line(empty), "")


class ScheduledDetailsAreScrubbed(unittest.TestCase):
	"""The reason this page cannot just show `details` verbatim.

	A scheduled job's traceback is recorded WITH local variables, and the
	restore path holds an argv with the database root password in it. This is
	the same leak the crash page turned up; a second page reading the same
	kind of text has to make the same defence.
	"""

	def test_a_password_in_a_recorded_argv_does_not_survive(self):
		details = (
			"Traceback (most recent call last):\n"
			"  File \"installer.py\", line 20, in _stream\n"
			"    argv = ['bench', 'restore', '--db-root-password', 'hunter2', 'site']\n"
			"OSError: boom"
		)
		scrubbed = siteconfig.scrub(details)
		self.assertNotIn("hunter2", scrubbed)
		# Still readable as a traceback afterwards — a scrub that ate the
		# whole line would take the fault with it.
		self.assertIn("OSError: boom", scrubbed)
		self.assertIn("--db-root-password", scrubbed)


if __name__ == "__main__":
	unittest.main()
