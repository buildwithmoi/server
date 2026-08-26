# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Restoring a site under a different name.

The move this makes possible: bring a backup up beside the live site under a
temporary name, check it, and swap the names over afterwards. Restoring over
the live site to find out whether the backup is any good is the thing worth not
doing, and until now it was the only thing on offer.
"""

from __future__ import annotations

import unittest

from server.bench import steps
from server.remote import runner


PLAN = {
	"target_bench": "frappe-bench-senchi",
	"source_server_name": "hetzner-snapshot",
	"source_bench": "frappe-bench-senchi",
	"bench_exists": True,
	"apps": [],
	"sites": [
		{"site_name": "senchi.example.com", "exists_here": True},
		{"site_name": "hr.example.com", "exists_here": False},
	],
}


class RenamingInAMove(unittest.TestCase):
	def test_the_source_and_target_names_are_separate_values(self):
		actions = runner.build_actions(PLAN, renames={"senchi.example.com": "test.senchi.example.com"})
		restore = next(a for a in actions if a["kind"] == runner.KIND_RESTORE and a["remote_site"] == "senchi.example.com")
		self.assertEqual(restore["site"], "test.senchi.example.com")
		self.assertEqual(restore["remote_site"], "senchi.example.com")

	def test_a_renamed_site_is_never_backed_up_first(self):
		# There is nothing there to back up. Asking bench to back up a site
		# that does not exist fails the job before it starts.
		actions = runner.build_actions(
			PLAN, backup_first=True, renames={"senchi.example.com": "test.senchi.example.com"}
		)
		renamed = next(a for a in actions if a["site"] == "test.senchi.example.com")
		self.assertFalse(renamed["backup_first"])

	def test_an_unrenamed_site_that_exists_here_still_is(self):
		actions = runner.build_actions(PLAN, backup_first=True)
		replaced = next(a for a in actions if a["site"] == "senchi.example.com")
		self.assertTrue(replaced["backup_first"])

	def test_the_label_says_both_names(self):
		actions = runner.build_actions(PLAN, renames={"senchi.example.com": "test.senchi.example.com"})
		renamed = next(a for a in actions if a["site"] == "test.senchi.example.com")
		self.assertIn("senchi.example.com → test.senchi.example.com", renamed["label"])

	def test_no_renames_behaves_exactly_as_before(self):
		self.assertEqual(runner.build_actions(PLAN), runner.build_actions(PLAN, renames={}))
		self.assertEqual(runner.build_actions(PLAN), runner.build_actions(PLAN, renames=None))


class TheDomainStep(unittest.TestCase):
	def test_it_is_announced_only_when_a_domain_was_asked_for(self):
		keys = [s.key for s in steps.for_restore(False, create_site=True, with_domain=True)]
		self.assertIn("domain", keys)
		self.assertNotIn("domain", [s.key for s in steps.for_restore(False, create_site=True)])

	def test_it_comes_after_the_restore_and_not_after_the_create(self):
		# A record pointing at a site that failed to restore sends real traffic
		# at a half-built one, and the record outlives the mistake.
		keys = [s.key for s in steps.for_restore(False, create_site=True, with_domain=True)]
		self.assertGreater(keys.index("domain"), keys.index("restore"))


if __name__ == "__main__":
	unittest.main()


class WhoseBackupIsIt(unittest.TestCase):
	"""The bug the rename created, and the check it nearly broke.

	Backups live in the directory of the site they were taken from. Restoring
	one under a NEW name and then looking for it under the target's name finds
	an empty directory and reports, wrongly, that the backup was rotated away.
	Found by running it, not by reading it.
	"""

	@staticmethod
	def _backup_site(install_on_site, restore_from_site):
		# The property read off a stand-in rather than a real Document: building
		# one needs a site connection, and what is being tested is two fields
		# and an `or`.
		from server.server.doctype.app_install_request.app_install_request import AppInstallRequest

		stub = type(
			"Stub", (), {"install_on_site": install_on_site, "restore_from_site": restore_from_site}
		)()
		return AppInstallRequest.backup_site.fget(stub)

	def test_the_backup_site_defaults_to_the_target(self):
		self.assertEqual(self._backup_site("live.example.com", None), "live.example.com")

	def test_a_rename_reads_the_source_site_instead(self):
		self.assertEqual(
			self._backup_site("test.live.example.com", "live.example.com"), "live.example.com"
		)

	def test_an_empty_value_is_not_a_rename(self):
		self.assertEqual(self._backup_site("live.example.com", "   "), "live.example.com")

	def test_the_wrong_site_check_compares_against_the_source(self):
		# Right-backup-wrong-site is the check that stops a restore looking
		# completely normal until the data is already replaced. Under a rename
		# the two names differ ON PURPOSE, and comparing against the target
		# would report the deliberate act as the accident.
		import inspect

		from server.bench import installer

		source = inspect.getsource(installer._preflight_restore)
		self.assertIn("describe_mismatch(backup, request.backup_site)", source)
