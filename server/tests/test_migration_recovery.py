# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A migration that was never told its job had finished.

The chain advances from `installer.finish`, which calls `on_job_finished`
inside a try/except because nothing on the way out of a job may raise
(Invariant 3). The price of that wrapping is that when the ADVANCE is what
fails, the job ends and the migration is never told: it says Running for ever,
the Continue button never appears — it only shows for Paused — and the only
record is a line in a log file nobody reads.

What the operator saw: a failure notification over a page that said it was
still going, and then the notification took itself away.
"""

from __future__ import annotations

import inspect
import unittest

import frappe

from server import api
from server.remote import runner


class TheRepairIsScheduled(unittest.TestCase):
	def test_reconcile_runs_on_the_scheduler(self):
		from server import hooks

		scheduled = set()
		for slot in hooks.scheduler_events.values():
			if isinstance(slot, dict):
				for methods in slot.values():
					scheduled.update(methods)
			else:
				scheduled.update(slot)
		self.assertIn("server.remote.runner.reconcile_migrations", scheduled)

	def test_reading_the_page_repairs_but_never_starts_anything(self):
		# The read path marks a stuck migration Paused, which is what makes
		# Continue appear. It must NOT start the next job: a page load is not
		# a place for a side effect that spends an hour of somebody's disk.
		source = inspect.getsource(api.bench_migration)
		self.assertIn('doc.db_set("status", "Paused"', source)
		self.assertNotIn("start_next", source)

	def test_the_scheduled_repair_is_the_half_that_does(self):
		source = inspect.getsource(runner.reconcile_migrations)
		self.assertIn("start_next", source)
		self.assertIn("on_job_finished", source)

	def test_it_leaves_a_job_still_running_alone(self):
		source = inspect.getsource(runner.reconcile_migrations)
		self.assertIn('("Queued", "Running")', source)


class TheDockKeepsFailures(unittest.TestCase):
	"""The notification that took itself away.

	A terminal job used to be dismissed after twenty seconds whatever its
	outcome — long enough to notice a red toast, not long enough to read it.
	The one job whose result had to be read was the one that vanished.
	"""

	def test_only_a_successful_job_is_auto_dismissed(self):
		import pathlib

		source = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "jobs.ts"
		).read_text()
		self.assertIn('data.is_terminal && data.status === "Success"', source)


class TheLinkGoesToTheJob(unittest.TestCase):
	"""Three kinds of action, three different log pages.

	A clone made by a migration is an App Install, a bench build is a
	Deployment and a site move is a Restoration. Sending all three to one of
	them is how clicking the failing step opened a page with nothing on it —
	and why the Bench Restoration log was empty after a migration that failed
	while cloning.
	"""

	def test_each_kind_maps_to_the_page_that_holds_it(self):
		import pathlib

		source = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		for kind, route in (
			(runner.KIND_RESTORE, "RestoreLogs"),
			(runner.KIND_PROVISION, "DeploymentLogs"),
			(runner.KIND_CLONE, "InstallLogs"),
		):
			self.assertIn(f"{kind}: \"{route}\"", source)

	def test_the_link_carries_the_job_name(self):
		import pathlib

		source = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		self.assertIn("query: { job: jobFor(i).name }", source)


class TheFailureReasonTravels(unittest.TestCase):
	def setUp(self):
		if not frappe.db:
			self.skipTest("needs a site")

	def test_the_migration_payload_carries_why_a_job_stopped(self):
		source = inspect.getsource(api.bench_migration)
		self.assertIn("error_summary", source)
		self.assertIn("exit_code", source)


if __name__ == "__main__":
	unittest.main()
