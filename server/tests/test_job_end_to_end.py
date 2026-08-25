# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The whole job body, run for real.

This file exists because of a specific gap. Everything else tests `_stream`,
the argv builders and the step machine in isolation — all of which passed while
`run_install_request` was broken by a reference to a variable that had been
deleted. The NameError fired inside `emit()`, which every failure path calls on
its way out, so the handler reporting the first error raised a second one and
the job died with its row still saying Running. It sat spinning in the dock
until someone noticed by eye.

So these run the actual function against the actual bench and assert the two
things no unit test was checking: that a job reaches a terminal status, and
that it does so even when the work fails.
"""

from __future__ import annotations

import json
import unittest

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False

if _HAS_SITE:
	from server.bench import installer

TERMINAL = ("Success", "Completed With Warnings", "Failed", "Cancelled")


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestJobReachesATerminalStatus(unittest.TestCase):
	"""A job that never finishes is worse than one that fails."""

	def setUp(self):
		self.bench = frappe.db.get_value("Server Bench", {"is_active": 1}, "name")
		if not self.bench:
			self.skipTest("no active bench on this machine")
		self.site = frappe.db.get_value("Server Bench Site", {"parent": self.bench}, "site_name")
		self.created = []

	def tearDown(self):
		for name in self.created:
			frappe.db.sql("DELETE FROM `tabApp Install Request` WHERE name = %s", name)
		frappe.db.commit()

	def _run(self, skip_validate=False, **fields):
		doc = frappe.get_doc({"doctype": "App Install Request", "bench": self.bench, **fields})
		if skip_validate:
			# Simulates the real case the worker pre-flight guards: the record
			# was valid when it was saved, and the backup was rotated away
			# before the worker got to it. The doctype rightly refuses to
			# create one that is invalid up front, so that is bypassed here.
			doc.flags.ignore_validate = True
		doc.insert()
		frappe.db.commit()
		self.created.append(doc.name)
		# Synchronously, in this process — the point is to exercise the body,
		# not the queue.
		installer.run_install_request(doc.name)
		frappe.db.rollback()
		return frappe.get_doc("App Install Request", doc.name)

	def test_a_read_only_command_succeeds_and_records_its_steps(self):
		if not self.site:
			self.skipTest("no site on this bench")
		request = self._run(operation="Command", bench_command="site.list-apps", install_on_site=self.site)

		self.assertEqual(request.status, "Success")
		self.assertEqual(request.exit_code, 0)
		self.assertTrue(request.output, "the log was not persisted")
		steps = json.loads(request.steps or "[]")
		self.assertTrue(steps)
		self.assertTrue(all(s["status"] in ("Success", "Skipped") for s in steps), steps)

	def test_a_command_that_cannot_run_still_finishes(self):
		"""The path that was broken: a failure reported through emit()."""
		request = self._run(
			operation="Command", bench_command="site.list-apps", install_on_site="not-a-real.site"
		)
		self.assertIn(request.status, TERMINAL)
		self.assertEqual(request.status, "Failed")
		self.assertTrue(request.error_summary)

	def test_a_refused_preflight_finishes_rather_than_hanging(self):
		request = self._run(
			skip_validate=True,
			operation="Restore",
			install_on_site=self.site,
			restore_backup_key="gone",
		)
		self.assertIn(request.status, TERMINAL)
		self.assertEqual(request.exit_code, installer.NEVER_RAN)

	def test_no_step_is_left_running_when_the_job_ends(self):
		"""An abandoned step spins forever in the interface."""
		if not self.site:
			self.skipTest("no site on this bench")
		request = self._run(operation="Command", bench_command="site.list-apps", install_on_site=self.site)
		steps = json.loads(request.steps or "[]")
		self.assertFalse([s for s in steps if s["status"] in ("Running", "Pending")], steps)

	def test_a_finished_restore_keeps_no_credentials(self):
		request = self._run(
			skip_validate=True,
			operation="Restore",
			install_on_site=self.site,
			restore_backup_key="gone",
			restore_db_password="do-not-keep-me",
		)
		self.assertIn(request.status, TERMINAL)
		rows = frappe.db.sql(
			"""SELECT COUNT(*) FROM `__Auth`
			   WHERE doctype = 'App Install Request' AND name = %s""",
			request.name,
		)[0][0]
		self.assertEqual(rows, 0, "the database root password survived the job")


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestEmitNeverRaises(unittest.TestCase):
	"""emit() is called from every failure path, so it must not add one."""

	def test_a_broken_realtime_publish_does_not_kill_the_job(self):
		from unittest import mock

		bench = frappe.db.get_value("Server Bench", {"is_active": 1}, "name")
		site = frappe.db.get_value("Server Bench Site", {"parent": bench}, "site_name")
		if not (bench and site):
			self.skipTest("no active bench with a site")

		doc = frappe.get_doc(
			{
				"doctype": "App Install Request",
				"bench": bench,
				"operation": "Command",
				"bench_command": "site.list-apps",
				"install_on_site": site,
			}
		)
		doc.insert()
		frappe.db.commit()
		try:
			with mock.patch.object(
				installer.frappe, "publish_realtime", side_effect=RuntimeError("socket is down")
			):
				installer.run_install_request(doc.name)
			frappe.db.rollback()
			self.assertIn(frappe.db.get_value("App Install Request", doc.name, "status"), TERMINAL)
		finally:
			frappe.db.sql("DELETE FROM `tabApp Install Request` WHERE name = %s", doc.name)
			frappe.db.commit()


if __name__ == "__main__":
	unittest.main()
