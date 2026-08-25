# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Backup discovery and restore argv tests.

Frappe-free, and built against synthetic backup directories rather than this
machine's own backups — the grouping logic is the whole point and it has to be
provable against sets this machine does not happen to have (encrypted ones,
sets from another site, a stray tar with no dump beside it).
"""

from __future__ import annotations

import gzip
import os
import tempfile
import unittest

from server.bench import restore

BENCH_EXE = "/usr/local/bin/bench"
SITE = "erp.example.com"
SLUG = "erp_example_com"


def write(path: str, data: bytes = b"") -> None:
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, "wb") as handle:
		handle.write(data)


def make_set(root: str, site: str, stamp: str, slug: str, *, files=False, encrypted=False) -> str:
	directory = os.path.join(root, "sites", site, "private", "backups")
	dump = os.path.join(directory, f"{stamp}-{slug}-database.sql.gz")
	write(dump, b"NOTGZIP" if encrypted else gzip.compress(b"-- dump"))
	write(os.path.join(directory, f"{stamp}-{slug}-site_config_backup.json"), b"{}")
	if files:
		write(os.path.join(directory, f"{stamp}-{slug}-files.tar"), b"public")
		write(os.path.join(directory, f"{stamp}-{slug}-private-files.tar"), b"private")
	return dump


class TestNaming(unittest.TestCase):
	def test_every_backup_kind_is_recognised(self):
		for kind in (restore.KIND_DATABASE, restore.KIND_PUBLIC, restore.KIND_PRIVATE, restore.KIND_CONFIG):
			with self.subTest(kind=kind):
				match = restore.BACKUP_NAME.match(f"20260825_000007-{SLUG}-{kind}")
				self.assertIsNotNone(match)
				self.assertEqual(match["stamp"], "20260825_000007")
				self.assertEqual(match["site"], SLUG)

	def test_unrelated_files_are_ignored(self):
		for name in ("notes.txt", "database.sql.gz", "2026-site-database.sql.gz"):
			with self.subTest(name=name):
				self.assertIsNone(restore.BACKUP_NAME.match(name))

	def test_site_slug_matches_frappes_own(self):
		self.assertEqual(restore.site_slug("erp.example.com"), "erp_example_com")


class TestListBackups(unittest.TestCase):
	def test_four_files_become_one_set(self):
		"""The grouping is the point.

		Matching a dump to its files tars by hand is how you restore Tuesday's
		database over Friday's files.
		"""
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG, files=True)
			sets = restore.list_backups(root, SITE)

			self.assertEqual(len(sets), 1)
			one = sets[0]
			self.assertTrue(one.database.endswith("database.sql.gz"))
			self.assertTrue(one.public_files.endswith("files.tar"))
			self.assertTrue(one.private_files.endswith("private-files.tar"))
			self.assertTrue(one.has_files)

	def test_newest_first(self):
		with tempfile.TemporaryDirectory() as root:
			for stamp in ("20260823_010000", "20260825_000007", "20260824_180000"):
				make_set(root, SITE, stamp, SLUG)
			keys = [b.key for b in restore.list_backups(root, SITE)]
			self.assertEqual(keys, [f"{s}-{SLUG}" for s in ("20260825_000007", "20260824_180000", "20260823_010000")])

	def test_a_set_without_a_dump_is_not_a_backup(self):
		with tempfile.TemporaryDirectory() as root:
			directory = os.path.join(root, "sites", SITE, "private", "backups")
			write(os.path.join(directory, f"20260825_000007-{SLUG}-files.tar"), b"public")
			self.assertEqual(restore.list_backups(root, SITE), [])

	def test_backups_dropped_in_the_bench_directory_are_found(self):
		"""Copying a backup from another server into the bench is the point."""
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			write(os.path.join(root, f"20260825_000007-{SLUG}-database.sql.gz"), gzip.compress(b"x"))
			sets = restore.list_backups(root, SITE)
			self.assertEqual(len(sets), 1)
			self.assertEqual(sets[0].source, "bench")

	def test_the_same_backup_in_two_places_is_listed_once(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG)
			write(os.path.join(root, f"20260825_000007-{SLUG}-database.sql.gz"), gzip.compress(b"x"))
			self.assertEqual(len(restore.list_backups(root, SITE)), 1)

	def test_a_missing_directory_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(restore.list_backups(root, SITE), [])

	def test_encryption_is_detected_from_the_file_itself(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG, encrypted=True)
			self.assertTrue(restore.list_backups(root, SITE)[0].encrypted)

	def test_a_plain_gzip_dump_is_not_encrypted(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG)
			self.assertFalse(restore.list_backups(root, SITE)[0].encrypted)


class TestMismatch(unittest.TestCase):
	def test_another_sites_backup_is_listed_but_flagged(self):
		"""Listed, because staging-from-production is a real thing to do.

		Flagged, because it is the mistake that looks completely normal right
		up until the data has been replaced.
		"""
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			write(os.path.join(root, "20260825_000007-other_site_com-database.sql.gz"), gzip.compress(b"x"))
			sets = restore.list_backups(root, SITE)

			self.assertEqual(len(sets), 1)
			self.assertIn("other.site.com", restore.describe_mismatch(sets[0], SITE))

	def test_the_sites_own_backup_is_not_flagged(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG)
			self.assertEqual(restore.describe_mismatch(restore.list_backups(root, SITE)[0], SITE), "")


class TestFind(unittest.TestCase):
	def test_a_rotated_away_backup_is_refused_by_name(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			with self.assertRaises(restore.RestoreRefused):
				restore.find(root, SITE, "20260825_000007-erp_example_com")


class TestArgv(unittest.TestCase):
	def _backup(self, root, **kw):
		make_set(root, SITE, "20260825_000007", SLUG, **kw)
		return restore.list_backups(root, SITE)[0]

	def test_the_root_password_is_passed_because_bench_has_no_other_way(self):
		with tempfile.TemporaryDirectory() as root:
			argv = restore.build_argv(BENCH_EXE, SITE, self._backup(root), "s3cret")
			self.assertEqual(argv[:4], [BENCH_EXE, "--site", SITE, "restore"])
			self.assertEqual(argv[argv.index("--db-root-password") + 1], "s3cret")

	def test_no_password_is_refused_rather_than_prompted_for(self):
		with tempfile.TemporaryDirectory() as root:
			with self.assertRaises(restore.RestoreRefused):
				restore.build_argv(BENCH_EXE, SITE, self._backup(root), "")

	def test_an_encrypted_backup_without_its_key_is_refused(self):
		"""Refused BEFORE the run, because restore drops the database first.

		Finding out afterwards means an empty site and no way back.
		"""
		with tempfile.TemporaryDirectory() as root:
			backup = self._backup(root, encrypted=True)
			with self.assertRaises(restore.RestoreRefused):
				restore.build_argv(BENCH_EXE, SITE, backup, "pw")
			argv = restore.build_argv(BENCH_EXE, SITE, backup, "pw", encryption_key="k")
			self.assertIn("--encryption-key", argv)

	def test_files_are_only_included_when_the_set_has_them(self):
		with tempfile.TemporaryDirectory() as root:
			bare = self._backup(root)
			argv = restore.build_argv(BENCH_EXE, SITE, bare, "pw", with_public=True, with_private=True)
			self.assertNotIn("--with-public-files", argv)
			self.assertNotIn("--with-private-files", argv)

		with tempfile.TemporaryDirectory() as root:
			full = self._backup(root, files=True)
			argv = restore.build_argv(BENCH_EXE, SITE, full, "pw", with_public=True, with_private=True)
			self.assertIn("--with-public-files", argv)
			self.assertIn("--with-private-files", argv)

	def test_the_safety_backup_only_includes_files_when_files_are_at_risk(self):
		self.assertNotIn("--with-files", restore.build_backup_argv(BENCH_EXE, SITE, False))
		self.assertIn("--with-files", restore.build_backup_argv(BENCH_EXE, SITE, True))


class TestRedaction(unittest.TestCase):
	"""`command` is stored in the database and shown in the interface."""

	def test_every_secret_flag_is_masked(self):
		argv = [
			BENCH_EXE, "--site", SITE, "restore", "/tmp/dump.sql.gz",
			"--db-root-password", "s3cret",
			"--encryption-key", "k3y",
			"--admin-password", "adm1n",
		]
		shown = " ".join(restore.redact(argv))
		for secret in ("s3cret", "k3y", "adm1n"):
			self.assertNotIn(secret, shown)
		self.assertEqual(shown.count(restore.REDACTED), 3)

	def test_the_command_is_still_a_faithful_record(self):
		argv = [BENCH_EXE, "--site", SITE, "restore", "/tmp/dump.sql.gz", "--db-root-password", "s3cret"]
		shown = restore.redact(argv)
		self.assertEqual(len(shown), len(argv))
		self.assertEqual(shown[:6], argv[:6])

	def test_redaction_does_not_mutate_the_argv_that_runs(self):
		argv = [BENCH_EXE, "--db-root-password", "s3cret"]
		restore.redact(argv)
		self.assertEqual(argv[-1], "s3cret")

	def test_a_trailing_secret_flag_does_not_crash(self):
		self.assertEqual(restore.redact(["bench", "--db-root-password"]), ["bench", "--db-root-password"])


if __name__ == "__main__":
	unittest.main()
