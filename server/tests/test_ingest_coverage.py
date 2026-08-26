# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Separating "nothing happened" from "nobody looked".

The first read looks back `bootstrap_hours` — 24 by default — and then follows
a journal cursor. On a 7-day chart that leaves five days that were never read,
and they were drawn as zero-height bars: identical to a silent weekend, and the
opposite fact about a server.
"""

from __future__ import annotations

import unittest

from server.ssh import journal


class TheWindowReachesJournalctl(unittest.TestCase):
	"""The backfill is only real if `--since` actually widens."""

	def test_the_hours_become_the_since_argument(self):
		self.assertIn("--since=-168hours", journal.build_argv(cursor=None, since_hours=168))
		self.assertIn("--since=-24hours", journal.build_argv(cursor=None, since_hours=24))

	def test_a_cursor_suppresses_the_window_entirely(self):
		# This is why a backfill has to clear the checkpoint first: with a
		# cursor stored, journalctl is asked for everything AFTER it and the
		# window is never sent at all.
		argv = journal.build_argv(cursor="s=abc;i=1", since_hours=168)
		self.assertTrue(any(a.startswith("--after-cursor=") for a in argv))
		self.assertFalse(any(a.startswith("--since=") for a in argv))


class ResettingIsNotSaving(unittest.TestCase):
	"""The bug this nearly shipped with.

	`reset_position()` only mutates the document — inside the ingest, its
	caller goes on to save it. A backfill that called it on a freshly fetched
	document and never saved left the cursor in the database, so `--since` was
	never sent and the whole thing read exactly nothing while reporting
	success.
	"""

	def test_reset_position_does_not_persist_on_its_own(self):
		import inspect

		from server.server.doctype.server_ingest_checkpoint import server_ingest_checkpoint as cp

		source = inspect.getsource(cp.ServerIngestCheckpoint.reset_position)
		self.assertNotIn("self.save", source)

	def test_the_backfill_saves_what_it_resets(self):
		import inspect

		from server import api

		source = inspect.getsource(api.read_history)
		self.assertIn("reset_position()", source)
		self.assertIn("save(ignore_permissions=True)", source)


if __name__ == "__main__":
	unittest.main()
