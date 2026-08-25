# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Backup pruning tests.

Deleting a backup is destructive in a quiet way: nothing breaks today, and you
find out months later when the one you wanted is the one that went. The rules
that prevent that live in the module rather than in the interface, so this is
where they are proved.
"""

from __future__ import annotations

import gzip
import os
import tempfile
import time
import unittest

from server.bench import backups

SITE = "erp.example.com"
SLUG = "erp_example_com"


def make_sets(root: str, ages_in_days: list[float]) -> str:
	"""One backup set per age, newest first in the resulting listing."""
	directory = os.path.join(root, "sites", SITE, "private", "backups")
	os.makedirs(directory, exist_ok=True)
	now = time.time()
	for index, age in enumerate(ages_in_days):
		stamp = f"202608{20 - index:02d}_120000"
		path = os.path.join(directory, f"{stamp}-{SLUG}-database.sql.gz")
		with open(path, "wb") as handle:
			handle.write(gzip.compress(b"x" * 1000))
		when = now - age * 86400
		os.utime(path, (when, when))
	return directory


class TestKeepRules(unittest.TestCase):
	def test_the_newest_are_never_offered(self):
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [10, 11, 12, 13, 14])
			plan = backups.plan(root, SITE, keep=3)
			kept = [c for c in plan["candidates"] if not c["deletable"]]
			self.assertEqual(len(kept), 3)
			self.assertTrue(all("newest" in c["reason"] for c in kept))

	def test_nothing_under_a_day_old_is_ever_offered(self):
		"""Clearing space is usually something you do right before a restore."""
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [0, 0.1, 0.5, 0.9, 0.95, 0.99])
			plan = backups.plan(root, SITE, keep=2)
			self.assertEqual(plan["deletable"], [])

	def test_the_keep_floor_cannot_be_argued_below(self):
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [10, 11, 12])
			for asked in (0, -5, 1):
				with self.subTest(keep=asked):
					self.assertEqual(backups.plan(root, SITE, keep=asked)["keep"], backups.MIN_KEEP)

	def test_age_and_count_are_both_required(self):
		"""AND, not OR — otherwise "keep the last 5" quietly removes yesterday's
		backup on a site that takes six a day."""
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [2, 3, 4, 5, 6])
			plan = backups.plan(root, SITE, keep=2, older_than_days=30)
			self.assertEqual(plan["deletable"], [])

	def test_a_set_only_goes_when_both_conditions_hold(self):
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [1, 2, 40, 50])
			plan = backups.plan(root, SITE, keep=2, older_than_days=30)
			self.assertEqual(len(plan["deletable"]), 2)

	def test_age_comes_from_the_file_not_the_name(self):
		"""A backup named last month but copied in today is new, and must not be
		deleted as though it were old."""
		with tempfile.TemporaryDirectory() as root:
			directory = os.path.join(root, "sites", SITE, "private", "backups")
			os.makedirs(directory)
			for index in range(4):
				path = os.path.join(directory, f"202601{10 + index:02d}_120000-{SLUG}-database.sql.gz")
				with open(path, "wb") as handle:
					handle.write(gzip.compress(b"x"))
			# Every file written just now, despite January names.
			self.assertEqual(backups.plan(root, SITE, keep=2)["deletable"], [])

	def test_freed_only_counts_what_would_actually_go(self):
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [1, 2, 30, 40])
			plan = backups.plan(root, SITE, keep=2)
			expected = sum(c["size"] for c in plan["candidates"] if c["deletable"])
			self.assertEqual(plan["freed"], expected)
			self.assertGreater(plan["freed"], 0)

	def test_a_site_with_no_backups_plans_nothing(self):
		with tempfile.TemporaryDirectory() as root:
			plan = backups.plan(root, SITE)
			self.assertEqual(plan["candidates"], [])
			self.assertEqual(plan["freed"], 0)


class TestPrune(unittest.TestCase):
	def test_deletes_only_what_the_plan_allowed(self):
		with tempfile.TemporaryDirectory() as root:
			directory = make_sets(root, [1, 2, 30, 40, 50])
			plan = backups.plan(root, SITE, keep=2)
			before = len(os.listdir(directory))

			result = backups.prune(root, SITE, plan["deletable"], keep=2)
			self.assertEqual(len(result["deleted_sets"]), 3)
			self.assertEqual(len(os.listdir(directory)), before - 3)

	def test_a_protected_set_is_refused_even_when_asked_for(self):
		"""The plan is recomputed inside prune rather than trusted from outside."""
		with tempfile.TemporaryDirectory() as root:
			directory = make_sets(root, [1, 2, 30])
			plan = backups.plan(root, SITE, keep=2)
			protected = plan["candidates"][0]["key"]

			result = backups.prune(root, SITE, [protected], keep=2)
			self.assertEqual(result["deleted"], [])
			self.assertIn(protected, result["refused"])
			self.assertEqual(len(os.listdir(directory)), 3)

	def test_a_fabricated_key_deletes_nothing(self):
		with tempfile.TemporaryDirectory() as root:
			directory = make_sets(root, [1, 2, 30])
			result = backups.prune(root, SITE, ["../../etc/passwd", "made-up"], keep=2)
			self.assertEqual(result["deleted"], [])
			self.assertEqual(sorted(result["refused"]), ["../../etc/passwd", "made-up"])
			self.assertEqual(len(os.listdir(directory)), 3)

	def test_an_empty_request_deletes_nothing(self):
		with tempfile.TemporaryDirectory() as root:
			directory = make_sets(root, [1, 2, 30])
			self.assertEqual(backups.prune(root, SITE, [], keep=2)["deleted"], [])
			self.assertEqual(len(os.listdir(directory)), 3)

	def test_a_tightened_keep_between_plan_and_prune_is_respected(self):
		"""A scheduled backup landing in between shifts what "newest" means."""
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [1, 2, 30, 40])
			plan = backups.plan(root, SITE, keep=2)
			# Same keys, but now asked to keep everything.
			result = backups.prune(root, SITE, plan["deletable"], keep=10)
			self.assertEqual(result["deleted"], [])

	def test_freed_reports_the_bytes_actually_removed(self):
		with tempfile.TemporaryDirectory() as root:
			make_sets(root, [1, 2, 30, 40])
			plan = backups.plan(root, SITE, keep=2)
			result = backups.prune(root, SITE, plan["deletable"], keep=2)
			self.assertEqual(result["freed"], plan["freed"])


class TestBackupArgv(unittest.TestCase):
	def test_files_are_opt_in(self):
		self.assertNotIn("--with-files", backups.build_backup_argv("/bin/bench", SITE))
		self.assertIn("--with-files", backups.build_backup_argv("/bin/bench", SITE, True))

	def test_targets_the_named_site(self):
		self.assertEqual(
			backups.build_backup_argv("/bin/bench", SITE)[:3], ["/bin/bench", "--site", SITE]
		)


if __name__ == "__main__":
	unittest.main()
