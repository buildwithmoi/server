# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A batch of clones finishes before anything stops.

Seven apps, and a failure on the first meant six more visits to get the rest —
when every one of those failures was independent and knowable in a single pass.

But not past the first site. Restoring into a bench missing an app the site
uses APPEARS to work: the site comes up and every DocType belonging to that app
is gone, surfacing days later as import errors nobody connects back to the
restore. That is the line a failed clone must not cross.
"""

from __future__ import annotations

import json
import unittest

from server.remote import runner


class States:
	"""A stand-in for the document, holding the same state the real one does."""

	PENDING = "Pending"
	DONE = "Success"
	FAILED = "Failed"

	def __init__(self, actions):
		self._actions = actions
		self.action_states = json.dumps([self.PENDING] * len(actions))
		self.current_action = 0

	def actions(self):
		return self._actions

	def describe(self, index):
		return self._actions[index]["label"]

	def db_set(self, *args, **kwargs):
		if args and isinstance(args[0], str) and args[0] == "action_states":
			self.action_states = args[1]

	# The three methods under test, taken from the real class so the logic is
	# not reimplemented here.
	states = None
	set_state = None
	next_pending = None
	failed_indexes = None


def _bind():
	from server.server.doctype.bench_migration.bench_migration import BenchMigration

	for name in ("states", "set_state", "next_pending", "failed_indexes"):
		setattr(States, name, getattr(BenchMigration, name))


ACTIONS = [
	{"kind": runner.KIND_CLONE, "label": "Clone cs_hrms"},
	{"kind": runner.KIND_CLONE, "label": "Clone erpnext"},
	{"kind": runner.KIND_CLONE, "label": "Clone hrms"},
	{"kind": runner.KIND_RESTORE, "label": "Move senchi.example.com"},
]


class SteppingOverAFailedClone(unittest.TestCase):
	def setUp(self):
		_bind()
		self.doc = States(list(ACTIONS))

	def test_the_next_action_after_a_failure_is_the_one_after_it(self):
		self.doc.set_state(0, States.FAILED)
		self.assertEqual(self.doc.next_pending(), 1)

	def test_a_failure_is_not_retried_inside_the_same_run(self):
		# A clone that fails for a reason on GitHub fails identically a second
		# later; retrying in place would loop.
		self.doc.set_state(0, States.FAILED)
		self.doc.set_state(1, States.DONE)
		self.doc.set_state(2, States.DONE)
		self.assertEqual(self.doc.next_pending(), 3)
		self.assertEqual(self.doc.failed_indexes(), [0])

	def test_everything_pending_starts_at_the_beginning(self):
		self.assertEqual(self.doc.next_pending(), 0)
		self.assertEqual(self.doc.failed_indexes(), [])

	def test_all_done_means_past_the_end(self):
		for i in range(len(ACTIONS)):
			self.doc.set_state(i, States.DONE)
		self.assertEqual(self.doc.next_pending(), len(ACTIONS))

	def test_a_migration_from_before_this_reconstructs_its_states(self):
		# Older rows carry no states. Everything before `current_action` is
		# known to have succeeded — that is what advancing the pointer meant.
		old = States(list(ACTIONS))
		old.action_states = None
		old.current_action = 2
		self.assertEqual(old.states(), ["Success", "Success", "Pending", "Pending"])


class WhereTheLineIs(unittest.TestCase):
	"""Which kinds stop the run, asserted against the code that decides."""

	def test_only_a_clone_is_stepped_over(self):
		import inspect

		source = inspect.getsource(runner.on_job_finished)
		self.assertIn("if kind == KIND_CLONE:", source)

	def test_a_restore_will_not_start_while_a_clone_is_outstanding(self):
		import inspect

		source = inspect.getsource(runner.start_next)
		self.assertIn('if action["kind"] == KIND_RESTORE and failed:', source)

	def test_continue_retries_only_what_failed(self):
		import inspect

		from server import api

		source = inspect.getsource(api.resume_bench_migration)
		self.assertIn("failed_indexes()", source)
		self.assertIn("doc.PENDING", source)


class AFailedPostinstallIsNotAFailedClone(unittest.TestCase):
	"""The app landed; its frontend dependencies did not.

	`bench get-app` runs `yarn install` in the app directory after the clone,
	the checkout and `uv pip install -e` have all succeeded — and that runs
	whatever postinstall the app declares. An app whose postinstall does
	`cd roster && yarn install` on a branch with no `roster` fails there, and
	the whole clone was reported as a failure.
	"""

	OUTPUT = (
		"$ cd roster && yarn install --check-files\n"
		"/bin/sh: 1: cd: can't cd to roster\n"
		"error Command failed with exit code 2.\n"
		"ERROR: yarn install --check-files\n"
		"bench.exceptions.CommandFailedError: yarn install --check-files\n"
	)

	def test_it_is_recognised(self):
		from server.bench import installer

		self.assertTrue(installer._FRONTEND_POSTSTEP.search(self.OUTPUT))

	def test_it_is_not_confused_with_the_supervisor_one(self):
		from server.bench import installer

		self.assertIsNone(installer._SUPERVISOR_POSTSTEP.search(self.OUTPUT))

	def test_an_ordinary_clone_failure_is_still_a_failure(self):
		from server.bench import installer

		denied = "ERROR: Repository not found.\nfatal: Could not read from remote repository.\n"
		self.assertIsNone(installer._FRONTEND_POSTSTEP.search(denied))
		self.assertIsNone(installer._SUPERVISOR_POSTSTEP.search(denied))


if __name__ == "__main__":
	unittest.main()


class PausingMustNotThrowAwayTheKey(unittest.TestCase):
	"""`finish("Paused")` cleared the database password.

	Correct for something that is over; fatal for something meant to be
	resumed. Creating a site and restoring one both need that password, and
	without it the only way forward is to start the whole migration again —
	re-cloning apps that are already there. Found by walking a migration
	through a failed clone and watching Continue refuse.
	"""

	def test_pause_keeps_the_secret_and_finish_does_not(self):
		import inspect

		from server.server.doctype.bench_migration.bench_migration import BenchMigration

		self.assertNotIn("clear_secret", inspect.getsource(BenchMigration.pause))
		self.assertIn("clear_secret", inspect.getsource(BenchMigration.finish))

	def test_nothing_pauses_through_finish(self):
		import inspect

		from server.remote import runner

		source = inspect.getsource(runner)
		self.assertNotIn('finish(\n\t\t\t\t"Paused"', source)
		self.assertNotIn('finish("Paused"', source)
