# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Moving a whole bench, one ordinary job at a time.

WHY THIS IS A CHAIN AND NOT ONE BIG JOB. Moving a bench with eight sites is
hours of work. As a single job it would be one row that either succeeds or
fails, with one log holding everything, and an interruption anywhere would
mean starting again — including the four gigabytes that had already moved.

So the plan becomes a list of actions and each action is an ordinary
`App Install Request`: a Provision, a Clone, a Restore. Each one shows in the
dock, gets its own entry in the deployment or restoration log, is cancellable
on its own, and — the part that matters at three in the morning — a migration
that stopped can be continued from where it stopped rather than restarted.

`current_action` is the whole state. Advancing is done from `installer.finish`,
which is the single terminal point every job passes through, so a chain cannot
be left dangling by a path that returned early.

WHAT IT DOES NOT DO. It does not decide anything the operator has not already
seen. `remote.migrate.build` produces the plan, the interface shows it — which
apps will be cloned, which sites created, which REPLACED — and only then is a
migration created from it. Nothing here discovers work while it runs.
"""

import json

import frappe
from frappe.model.document import Document

#: Terminal states of the individual jobs, mapped to what they mean for the
#: chain. A warning is not a failure: `bench get-app` exits non-zero from a
#: trailing supervisorctl call on a box with no passwordless sudo, long after
#: the app is on disk, and stopping a migration for that would be wrong.
CONTINUE_ON = ("Success", "Completed With Warnings")


class BenchMigration(Document):
	def actions(self) -> list[dict]:
		try:
			return json.loads(self.actions_json or "[]")
		except ValueError:
			return []

	#: Per-action outcome. `current_action` alone is a pointer, and a pointer
	#: cannot say "the fourth app did not clone but the fifth and sixth did" —
	#: which is exactly what a batch of clones has to be able to say.
	PENDING = "Pending"
	DONE = "Success"
	FAILED = "Failed"

	def states(self) -> list[str]:
		"""One state per action, defaulted for a migration started before this.

		Older rows have no states at all. Everything before `current_action` is
		known to have succeeded — that is what advancing the pointer meant — so
		the list is reconstructed from it rather than the row being treated as
		broken.
		"""
		count = len(self.actions())
		try:
			stored = json.loads(self.action_states or "[]")
		except ValueError:
			stored = []
		if len(stored) == count and all(stored):
			return stored
		at = int(self.current_action or 0)
		return [self.DONE if i < at else self.PENDING for i in range(count)]

	def set_state(self, index: int, state: str) -> None:
		states = self.states()
		if 0 <= index < len(states):
			states[index] = state
			self.db_set("action_states", json.dumps(states), update_modified=False)

	def next_pending(self) -> int:
		"""The next action to run, skipping ones that already failed.

		Failed ones are stepped over rather than retried here: a clone that
		fails for a reason on GitHub fails identically a second later, and
		stopping the whole batch at the first one is what made moving a bench
		of seven apps a seven-visit job. They are retried on Continue, once
		somebody has fixed something.
		"""
		states = self.states()
		for index, state in enumerate(states):
			if state == self.PENDING:
				return index
		return len(states)

	def failed_indexes(self) -> list[int]:
		return [i for i, state in enumerate(self.states()) if state == self.FAILED]

	def get_secret(self) -> str:
		return self.get_password("db_password", raise_exception=False) or ""

	def clear_secret(self) -> None:
		"""Drop the database password once the migration is over.

		Same rule as a restore: it is needed for the length of the work and is
		a standing risk afterwards. `remove_encrypted_password` is what deletes
		it — clearing the column only removes the mask.
		"""
		from frappe.utils.password import remove_encrypted_password

		remove_encrypted_password(self.doctype, self.name, "db_password")
		if self.db_password:
			self.db_set("db_password", None, update_modified=False)

	def describe(self, index: int) -> str:
		actions = self.actions()
		if 0 <= index < len(actions):
			return actions[index].get("label") or actions[index].get("kind") or "?"
		return "—"

	def pause(self, note: str = "") -> None:
		"""Stop, but keep what is needed to continue.

		NOT `finish("Paused")`. `finish` clears the database password, which is
		correct for something that is over and fatal for something that is
		meant to be resumed: creating and restoring a site both need it, and
		without it the only way forward is to start the whole migration again.
		Caught by walking a migration through a failed clone and finding
		Continue refusing to run.
		"""
		self.db_set(
			{"status": "Paused", "notes": (note or self.notes or "")[:1000] or None},
			update_modified=False,
		)
		frappe.db.commit()

	def finish(self, status: str, note: str = "") -> None:
		self.db_set(
			{
				"status": status,
				"finished_at": frappe.utils.now_datetime(),
				"notes": (note or self.notes or "")[:1000] or None,
			},
			update_modified=False,
		)
		self.clear_secret()
		frappe.db.commit()
