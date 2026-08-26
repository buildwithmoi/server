# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Planning a whole-bench move, before any of it starts.

Moving eight benches is a sequence of long jobs. The useful thing is not
starting them — it is seeing, before starting any, what will be built and what
is missing. A migration that stops forty minutes in because one repository is
unreachable is what this exists to prevent, so everything here is answerable
from two bench descriptions and runs nothing.
"""

import unittest

from server.remote import migrate, runner

REMOTE = {
	"name": "fb-16-1",
	"frappe_branch": "version-16",
	"apps": [
		{"app_name": "frappe", "branch": "version-16"},
		{"app_name": "erpnext", "branch": "version-16", "git_url": "git@github.com:frappe/erpnext.git"},
		{"app_name": "hrms", "branch": "version-16", "git_url": "git@github.com:frappe/hrms.git"},
	],
	"sites": [
		{"site_name": "new.test", "installed_apps": ["frappe", "erpnext"]},
		{"site_name": "existing.test", "installed_apps": ["frappe", "hrms"]},
	],
}


class TestAgainstABenchThatDoesNotExistYet(unittest.TestCase):
	"""The case the whole feature is for."""

	def setUp(self):
		self.plan = migrate.build("old-box", REMOTE, None, "fb-16-new")

	def test_it_is_not_an_error(self):
		self.assertEqual(self.plan.target_bench, "fb-16-new")
		self.assertFalse(self.plan.bench_exists)

	def test_every_app_is_missing(self):
		self.assertEqual(sorted(a.app_name for a in self.plan.missing_apps), ["erpnext", "hrms"])

	def test_frappe_is_not_an_app_to_clone(self):
		"""It is what a bench IS, and arrives with `bench init`."""
		self.assertNotIn("frappe", [a.app_name for a in self.plan.apps])

	def test_the_frappe_version_carries_over(self):
		"""The new bench has to be built on the version the sites came from."""
		self.assertEqual(self.plan.frappe_version, "16")

	def test_every_site_is_a_creation(self):
		self.assertTrue(all(not s.exists_here for s in self.plan.sites))

	def test_the_note_says_the_bench_is_built_first(self):
		self.assertTrue(any("does not exist here yet" in n for n in self.plan.notes))


class TestAgainstABenchThatIsAlreadyHere(unittest.TestCase):
	def setUp(self):
		local = {
			"apps": [{"app_name": "erpnext", "branch": "version-15"}],
			"sites": [{"site_name": "existing.test"}],
		}
		self.plan = migrate.build("old-box", REMOTE, local, "fb-16-4")

	def test_an_app_already_here_is_not_cloned_again(self):
		self.assertEqual([a.app_name for a in self.plan.missing_apps], ["hrms"])

	def test_a_branch_difference_is_reported_but_is_not_missing(self):
		"""Running the same app from different branches is a real choice, not
		a fault — but it is the most common reason a restore succeeds and then
		behaves oddly, so it is surfaced."""
		self.assertEqual([a.app_name for a in self.plan.branch_differences], ["erpnext"])
		self.assertTrue(next(a for a in self.plan.apps if a.app_name == "erpnext").present)

	def test_a_site_that_exists_here_is_a_replacement(self):
		by_name = {s.site_name: s for s in self.plan.sites}
		self.assertTrue(by_name["existing.test"].exists_here)
		self.assertEqual(by_name["existing.test"].action, "replace")
		self.assertEqual(by_name["new.test"].action, "create then restore")

	def test_replacing_is_called_out_in_the_notes(self):
		"""Overwriting a site somebody is using is a different decision from
		adding one, and the plan should not let that pass silently."""
		self.assertTrue(any("REPLACED" in n for n in self.plan.notes))

	def test_it_is_not_ready_while_an_app_is_missing(self):
		self.assertFalse(self.plan.ready)


class TestOrdering(unittest.TestCase):
	def test_new_sites_move_before_replacements(self):
		"""An interrupted migration should be interrupted having ADDED sites
		rather than having half-replaced existing ones. The first is progress;
		the second is damage."""
		local = {"apps": [], "sites": [{"site_name": "existing.test"}]}
		plan = migrate.build("old-box", REMOTE, local, "fb-16-4")
		self.assertEqual(
			[s.site_name for s in migrate.order_sites(plan)], ["new.test", "existing.test"]
		)


class TestReadiness(unittest.TestCase):
	def test_ready_only_when_the_bench_and_every_app_are_here(self):
		local = {
			"apps": [{"app_name": "erpnext", "branch": "version-16"}, {"app_name": "hrms", "branch": "version-16"}],
			"sites": [],
		}
		self.assertTrue(migrate.build("old-box", REMOTE, local, "fb-16-4").ready)

	def test_not_ready_when_the_bench_is_absent_even_with_no_apps(self):
		bare = {"name": "x", "frappe_branch": "version-16", "apps": [], "sites": []}
		self.assertFalse(migrate.build("old-box", bare, None, "fb-new").ready)


class TestAwkwardInput(unittest.TestCase):
	def test_a_bench_with_no_sites_says_so(self):
		bare = {"name": "x", "frappe_branch": "version-16", "apps": [], "sites": []}
		plan = migrate.build("old-box", bare, {"apps": [], "sites": []}, "here")
		self.assertTrue(any("no sites" in n for n in plan.notes))

	def test_entries_with_no_name_are_skipped_rather_than_crashing(self):
		"""The remote's answer is data from another machine."""
		messy = {"name": "x", "apps": [{"branch": "v"}, {"app_name": ""}], "sites": [{"installed_apps": []}]}
		plan = migrate.build("old-box", messy, None, "here")
		self.assertEqual(plan.apps, ())
		self.assertEqual(plan.sites, ())

	def test_it_serialises_for_the_interface(self):
		data = migrate.build("old-box", REMOTE, None, "fb-new").as_dict()
		self.assertIn("missing_apps", data)
		self.assertTrue(all("action" in a for a in data["apps"]))
		self.assertTrue(all("action" in s for s in data["sites"]))


class MovingOntoABenchThatIsAlreadyHere(unittest.TestCase):
	"""What "same name" means, which is not one thing.

	A target bench of the same name is USED, not rebuilt: `bench init` is
	skipped, only missing apps are cloned, and a site of the same name is
	replaced rather than added. The version of that existing bench is the part
	nothing else would notice.
	"""

	REMOTE = {
		"name": "frappe-bench-senchi",
		"frappe_branch": "version-15",
		"apps": [
			{"app_name": "frappe", "branch": "version-15"},
			{"app_name": "erpnext", "branch": "version-15"},
			{"app_name": "hrms", "branch": "version-15"},
		],
		"sites": [{"site_name": "senchi.example.com", "installed_apps": ["erpnext", "hrms"]}],
	}

	def _local(self, **overrides):
		base = {
			"name": "frappe-bench-senchi",
			"frappe_branch": "version-15",
			"apps": [{"app_name": "erpnext", "branch": "version-15"}],
			"sites": [{"site_name": "senchi.example.com"}],
		}
		base.update(overrides)
		return base

	def test_an_existing_bench_is_not_rebuilt(self):
		plan = migrate.build("hetzner", self.REMOTE, self._local(), "frappe-bench-senchi")
		self.assertTrue(plan.bench_exists)
		self.assertNotIn(
			runner.KIND_PROVISION, [a["kind"] for a in runner.build_actions({**plan.as_dict(), "source_server_name": "hetzner"})]
		)

	def test_only_the_missing_apps_are_cloned(self):
		plan = migrate.build("hetzner", self.REMOTE, self._local(), "frappe-bench-senchi")
		cloned = [a["repo"] for a in runner.build_actions({**plan.as_dict(), "source_server_name": "hetzner"}) if a["kind"] == runner.KIND_CLONE]
		# erpnext is here; frappe is never cloned — it is what a bench IS.
		self.assertEqual(cloned, ["hrms"])

	def test_a_site_of_the_same_name_is_replaced_and_says_so(self):
		plan = migrate.build("hetzner", self.REMOTE, self._local(), "frappe-bench-senchi")
		self.assertEqual(plan.sites[0].action, "replace")
		self.assertTrue(any("REPLACED" in n for n in plan.notes))

	def test_a_different_major_version_is_reported(self):
		# Nothing else in the plan would notice. `bench init` is skipped, so
		# the version is whatever that bench was built as, and a v15 dump in a
		# v16 bench fails during migrate — after the database is replaced.
		plan = migrate.build(
			"hetzner", self.REMOTE, self._local(frappe_branch="version-16"), "frappe-bench-senchi"
		)
		self.assertFalse(plan.version_matches)
		self.assertTrue(any("VERSION MISMATCH" in n for n in plan.notes))

	def test_a_patch_level_difference_is_not_a_mismatch(self):
		plan = migrate.build(
			"hetzner", self.REMOTE, self._local(frappe_branch="15.116.0"), "frappe-bench-senchi"
		)
		self.assertTrue(plan.version_matches)

	def test_a_bench_being_built_is_never_a_mismatch(self):
		# It is built to match, by construction.
		plan = migrate.build("hetzner", self.REMOTE, None, "frappe-bench-new")
		self.assertTrue(plan.version_matches)
