# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Continuing a move that was stopped by hand.

Stopping a migration ends the chain. It does not void the plan, and it does not
undo the bench that was built or the apps already cloned. Refusing to continue
one meant a new migration was the only way forward — which is precisely the
thing the resume path exists to avoid, and it was reached by pressing Stop.
"""

from __future__ import annotations

import inspect
import pathlib
import unittest

from server import api


class CancelledIsStoppedNotVoid(unittest.TestCase):
	def test_only_a_finished_move_refuses(self):
		source = inspect.getsource(api.resume_bench_migration)
		self.assertIn('if doc.status == "Success":', source)
		# The old guard turned Stop into a one-way door.
		self.assertNotIn('doc.status in ("Success", "Cancelled")', source)

	def test_it_leaves_the_terminal_state_before_asking_for_the_next_action(self):
		# `start_next` refuses to touch a Cancelled, Success or Failed
		# migration, so resuming one without this returned "skipped" and did
		# nothing at all — a button that reports success and acts on nothing.
		source = inspect.getsource(api.resume_bench_migration)
		self.assertIn('{"status": "Running", "finished_at": None}', source)

	def test_the_page_offers_continue_on_a_stopped_move(self):
		source = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		self.assertIn('["Paused", "Cancelled", "Failed"].includes(data.value?.status)', source)


class ThePasswordIsAskedForAgain(unittest.TestCase):
	"""It is cleared on every terminal state, deliberately.

	It is a database root password and is never kept longer than a run needs
	it. But "it was cleared, so start over" is an answer that costs an hour of
	re-cloning, so it is asked for instead.
	"""

	def test_resume_accepts_one(self):
		self.assertIn("db_root_password", inspect.signature(api.resume_bench_migration).parameters)

	def test_the_page_is_told_whether_it_will_be_needed(self):
		# Asked before the button acts, rather than failing after it is pressed.
		self.assertIn("needs_password", inspect.getsource(api.bench_migration))

	def test_the_refusal_names_what_to_do(self):
		# The string is wrapped across source lines, so the message is
		# reassembled the way the reader will see it.
		source = " ".join(inspect.getsource(api.resume_bench_migration).split())
		message = source.replace('" "', "")
		self.assertIn("Supply it again to continue", message)
		self.assertIn("nothing already done is repeated", message)


if __name__ == "__main__":
	unittest.main()
