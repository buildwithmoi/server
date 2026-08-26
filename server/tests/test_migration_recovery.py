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


class TheLinkTheChainHangsOn(unittest.TestCase):
	"""Nothing was writing `migration` onto the job.

	`on_job_finished` looks that field up to decide whether a job belongs to a
	migration, and no code path set it. So every step ran, finished, and the
	migration was never told: it sat at "step 0 of 9" with every action still
	marked waiting while the work had actually happened, and the next step was
	never started. The chain could not advance at all.
	"""

	def test_starting_an_action_stamps_the_job_with_its_migration(self):
		source = inspect.getsource(runner.start_next)
		self.assertIn('"migration": migration.name', source)

	def test_it_stamps_which_action_too(self):
		# Jobs used to be matched to actions by position, which held only
		# while every action produced exactly one job. An action already
		# satisfied on disk produces none, and every later job then slid up a
		# row — putting each failure against the wrong step.
		source = inspect.getsource(runner.start_next)
		self.assertIn('"migration_action": index', source)

	def test_the_page_reads_them_by_action_not_by_position(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		self.assertIn("job_for_action?.[index]", view)


class WatchingItWork(unittest.TestCase):
	"""A restore is minutes of pulling gigabytes, and "running" is not progress.

	Five minutes of an unchanging word is indistinguishable from a job that has
	hung — which is the state this migration was actually in twice.
	"""

	def test_the_running_step_shows_its_own_steps_and_output(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		self.assertIn("<JobSteps", view)
		self.assertIn("isLive(i)", view)

	def test_the_running_job_is_polled_faster_than_the_migration(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "Migration.vue"
		).read_text()
		self.assertIn("const LIVE_MS = 2000", view)

	def test_the_transfer_reports_bytes_as_it_goes(self):
		# What makes the tail worth watching during the long step.
		from server.bench import installer

		self.assertIn("progress.percent", inspect.getsource(installer._pull_from_remote))
