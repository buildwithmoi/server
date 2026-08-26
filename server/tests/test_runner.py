# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Turning a migration plan into an ordered list of jobs.

The ordering is the whole of it, and none of it is incidental: the bench has
to exist before an app can be cloned into it, every app has to be present
before a site that uses it is restored, and new sites go before replacements
so an interruption leaves sites ADDED rather than half-overwritten.
"""

import unittest

from server.remote import runner

PLAN_NEW_BENCH = {
	"target_bench": "fb-16-new",
	"source_bench": "fb-16-1",
	"source_server_name": "old-box",
	"frappe_version": "16",
	"bench_exists": False,
	"apps": [
		{"app_name": "erpnext", "branch": "version-16", "git_url": "git@x:erpnext.git", "present": False},
		{"app_name": "hrms", "branch": "version-16", "git_url": "git@x:hrms.git", "present": False},
	],
	"sites": [
		{"site_name": "b.test", "exists_here": False},
		{"site_name": "a.test", "exists_here": False},
	],
}

PLAN_EXISTING_BENCH = {
	**PLAN_NEW_BENCH,
	"target_bench": "fb-16-4",
	"bench_exists": True,
	"apps": [
		{"app_name": "erpnext", "branch": "version-16", "git_url": "git@x:erpnext.git", "present": True},
		{"app_name": "hrms", "branch": "version-16", "git_url": "git@x:hrms.git", "present": False},
	],
	"sites": [
		{"site_name": "replaced.test", "exists_here": True},
		{"site_name": "new.test", "exists_here": False},
	],
}


class TestBuildingAgainstANewBench(unittest.TestCase):
	def setUp(self):
		self.actions = runner.build_actions(PLAN_NEW_BENCH)

	def test_the_bench_is_built_first(self):
		self.assertEqual(self.actions[0]["kind"], runner.KIND_PROVISION)

	def test_the_apps_ride_along_with_the_build(self):
		"""Provision already clones apps, so a separate Clone per app would be
		a second trip for work the first one does."""
		provision = self.actions[0]
		self.assertEqual(sorted(a["repo"] for a in provision["apps"]), ["erpnext", "hrms"])
		self.assertNotIn(runner.KIND_CLONE, [a["kind"] for a in self.actions])

	def test_the_frappe_version_carries_over(self):
		self.assertEqual(self.actions[0]["frappe_version"], "16")

	def test_every_site_becomes_a_restore(self):
		restores = [a for a in self.actions if a["kind"] == runner.KIND_RESTORE]
		self.assertEqual(sorted(a["site"] for a in restores), ["a.test", "b.test"])

	def test_sites_come_after_the_bench(self):
		kinds = [a["kind"] for a in self.actions]
		self.assertLess(kinds.index(runner.KIND_PROVISION), kinds.index(runner.KIND_RESTORE))


class TestBuildingAgainstAnExistingBench(unittest.TestCase):
	def setUp(self):
		self.actions = runner.build_actions(PLAN_EXISTING_BENCH)

	def test_no_bench_is_built(self):
		self.assertNotIn(runner.KIND_PROVISION, [a["kind"] for a in self.actions])

	def test_only_the_missing_app_is_cloned(self):
		clones = [a for a in self.actions if a["kind"] == runner.KIND_CLONE]
		self.assertEqual([a["repo"] for a in clones], ["hrms"])

	def test_apps_are_cloned_before_any_site_is_restored(self):
		"""A site restored before its app is present is the silent failure the
		whole readiness check exists to prevent."""
		kinds = [a["kind"] for a in self.actions]
		self.assertLess(kinds.index(runner.KIND_CLONE), kinds.index(runner.KIND_RESTORE))

	def test_new_sites_move_before_replacements(self):
		restores = [a for a in self.actions if a["kind"] == runner.KIND_RESTORE]
		self.assertEqual([a["site"] for a in restores], ["new.test", "replaced.test"])

	def test_a_new_site_takes_no_safety_backup(self):
		"""There is nothing there to back up."""
		by_site = {a["site"]: a for a in self.actions if a["kind"] == runner.KIND_RESTORE}
		self.assertFalse(by_site["new.test"]["backup_first"])
		self.assertTrue(by_site["replaced.test"]["backup_first"])

	def test_turning_the_safety_backup_off_applies_to_replacements_too(self):
		actions = runner.build_actions(PLAN_EXISTING_BENCH, backup_first=False)
		by_site = {a["site"]: a for a in actions if a["kind"] == runner.KIND_RESTORE}
		self.assertFalse(by_site["replaced.test"]["backup_first"])


class TestOptions(unittest.TestCase):
	def test_files_can_be_left_behind(self):
		actions = runner.build_actions(PLAN_NEW_BENCH, with_files=False)
		self.assertTrue(all(not a["with_files"] for a in actions if a["kind"] == runner.KIND_RESTORE))

	def test_each_restore_names_the_server_by_docname(self):
		"""Two servers can share a display name; the action has to carry the
		one a Link field will resolve."""
		actions = runner.build_actions(PLAN_NEW_BENCH)
		restore = next(a for a in actions if a["kind"] == runner.KIND_RESTORE)
		self.assertEqual(restore["remote_server"], "old-box")

	def test_every_action_has_a_label_a_person_can_read(self):
		"""It is what the migration shows for "on action 3 of 9"."""
		for action in runner.build_actions(PLAN_EXISTING_BENCH):
			self.assertTrue(action["label"].strip())
			self.assertNotIn("None", action["label"])


class TestNothingToDo(unittest.TestCase):
	def test_a_bench_that_is_already_here_with_no_sites_yields_nothing(self):
		plan = {
			"target_bench": "fb-16-4", "source_bench": "x", "source_server_name": "old",
			"bench_exists": True, "apps": [{"app_name": "erpnext", "present": True}], "sites": [],
		}
		self.assertEqual(runner.build_actions(plan), [])
