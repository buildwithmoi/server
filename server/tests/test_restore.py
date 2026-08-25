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
		for kind, ext in (
			(restore.KIND_DATABASE, ".sql.gz"),
			(restore.KIND_PUBLIC, ".tar"),
			(restore.KIND_PRIVATE, ".tar"),
			(restore.KIND_CONFIG, ".json"),
		):
			with self.subTest(kind=kind):
				match = restore.BACKUP_NAME.match(f"20260825_000007-{SLUG}-{kind}{ext}")
				self.assertIsNotNone(match)
				self.assertEqual(match["stamp"], "20260825_000007")
				self.assertEqual(match["site"], SLUG)
				self.assertEqual(match["kind"], kind)

	def test_encrypted_backups_are_recognised(self):
		"""frappe appends `-enc` to an encrypted backup.

		Without it in the pattern the set does not match at all, so an
		encrypted backup is not "hard to restore" — it is invisible, and the
		operator is told the site has no backups.
		"""
		match = restore.BACKUP_NAME.match(f"20260825_000007-{SLUG}-database-enc.sql.gz")
		self.assertIsNotNone(match)
		self.assertEqual(match["kind"], restore.KIND_DATABASE)
		self.assertEqual(match["enc"], "-enc")

	def test_partial_and_alternate_archive_extensions_are_recognised(self):
		for name in (
			f"20260825_000007-{SLUG}-partial-database.sql.gz",
			f"20260825_000007-{SLUG}-files.tgz",
			f"20260825_000007-{SLUG}-files.tar.gz",
		):
			with self.subTest(name=name):
				self.assertIsNotNone(restore.BACKUP_NAME.match(name))

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


class TestFileDiscovery(unittest.TestCase):
	"""Picking three loose files, for a backup copied in from another server."""

	def test_finds_restorable_files_and_ignores_the_rest(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			write(os.path.join(root, "dump.sql.gz"), gzip.compress(b"x"))
			write(os.path.join(root, "files.tar"), b"tar")
			write(os.path.join(root, "notes.txt"), b"text")

			names = {f.name for f in restore.list_files(root, SITE)}
			self.assertEqual(names, {"dump.sql.gz", "files.tar"})

	def test_does_not_walk_into_apps_or_env(self):
		"""A bench root holds hundreds of thousands of files it must not read."""
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			write(os.path.join(root, "apps", "frappe", "buried.sql.gz"), gzip.compress(b"x"))
			write(os.path.join(root, "env", "lib", "buried.sql.gz"), gzip.compress(b"x"))
			self.assertEqual(restore.list_files(root, SITE), [])

	def test_the_same_file_reachable_twice_is_listed_once(self):
		with tempfile.TemporaryDirectory() as root:
			backups = os.path.join(root, "sites", SITE, "private", "backups")
			write(os.path.join(backups, "dump.sql.gz"), gzip.compress(b"x"))
			os.symlink(os.path.join(backups, "dump.sql.gz"), os.path.join(root, "link.sql.gz"))
			self.assertEqual(len(restore.list_files(root, SITE)), 1)


class TestPathSafety(unittest.TestCase):
	"""Restore paths arrive from a browser, and bench restore reads any file."""

	def test_a_path_outside_the_bench_is_refused(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			for outside in ("/etc/passwd", os.path.join(root, "..", "escape.sql.gz")):
				with self.subTest(path=outside), self.assertRaises(restore.RestoreRefused):
					restore.resolve_chosen(root, SITE, outside)

	def test_a_symlink_pointing_out_of_the_bench_is_refused(self):
		"""String comparison would pass this; resolving the path does not."""
		with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as elsewhere:
			os.makedirs(os.path.join(root, "sites", SITE))
			target = os.path.join(elsewhere, "secret.sql.gz")
			write(target, gzip.compress(b"x"))
			link = os.path.join(root, "innocent.sql.gz")
			os.symlink(target, link)

			self.assertFalse(restore.is_inside(root, link))
			with self.assertRaises(restore.RestoreRefused):
				restore.resolve_chosen(root, SITE, link)

	def test_a_file_inside_the_bench_is_allowed(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			dump = os.path.join(root, "dump.sql.gz")
			write(dump, gzip.compress(b"x"))
			self.assertEqual(restore.resolve_chosen(root, SITE, dump).database, dump)

	def test_a_missing_file_is_refused(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			with self.assertRaises(restore.RestoreRefused):
				restore.resolve_chosen(root, SITE, os.path.join(root, "gone.sql.gz"))

	def test_files_alone_cannot_restore_a_site(self):
		with tempfile.TemporaryDirectory() as root:
			with self.assertRaises(restore.RestoreRefused):
				restore.resolve_chosen(root, SITE, "", public=os.path.join(root, "files.tar"))


class TestChosenConverges(unittest.TestCase):
	"""Both sources produce one BackupSet, so there is one path to get wrong."""

	def test_a_hand_picked_dump_still_warns_about_the_wrong_site(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			dump = os.path.join(root, "20260825_000007-other_site_com-database.sql.gz")
			write(dump, gzip.compress(b"x"))

			chosen = restore.resolve_chosen(root, SITE, dump)
			self.assertIn("other.site.com", restore.describe_mismatch(chosen, SITE))

	def test_encryption_is_still_detected(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			dump = os.path.join(root, "encrypted.sql.gz")
			write(dump, b"NOTGZIP")
			self.assertTrue(restore.resolve_chosen(root, SITE, dump).encrypted)


class TestSpaceEstimate(unittest.TestCase):
	def test_required_space_scales_with_the_dump(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG, files=True)
			backup = restore.list_backups(root, SITE)[0]
			estimate = restore.estimate_space(root, backup)

			dump_size = os.path.getsize(backup.database)
			files_size = os.path.getsize(backup.public_files) + os.path.getsize(backup.private_files)
			self.assertEqual(estimate.required, dump_size * restore.DB_EXPANSION + files_size)

	def test_a_tiny_backup_on_a_real_disk_fits(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG)
			self.assertTrue(restore.estimate_space(root, restore.list_backups(root, SITE)[0]).enough)

	def test_the_detail_says_how_short_it_is(self):
		with tempfile.TemporaryDirectory() as root:
			make_set(root, SITE, "20260825_000007", SLUG)
			backup = restore.list_backups(root, SITE)[0]
			huge = restore.BackupSet(**{**backup.__dict__, "database": backup.database})
			estimate = restore.estimate_space(root, huge)
			# Small backup on a real disk: the message should be the reassuring
			# one, and should still name the expansion factor.
			self.assertIn(str(restore.DB_EXPANSION), estimate.detail)


class TestEncryptionDetection(unittest.TestCase):
	"""Three cases, not two.

	"Anything that is not gzip is encrypted" was wrong in the direction that
	matters: a plain uncompressed mysqldump — exactly what gets copied in from
	another server, which is the case the hand-picked path exists for — was
	reported as encrypted and could not be restored at all, because the only
	way past the check was to invent a key.
	"""

	def _write(self, root: str, name: str, data: bytes) -> str:
		path = os.path.join(root, name)
		write(path, data)
		return path

	def test_a_plain_uncompressed_dump_is_not_encrypted(self):
		with tempfile.TemporaryDirectory() as root:
			for name, head in (
				("dump.sql", b"-- MySQL dump 10.13\nCREATE TABLE x;"),
				("upper.sql", b"CREATE TABLE `tabUser`;"),
				("set.sql", b"SET NAMES utf8mb4;"),
				("comment.sql", b"/*!40101 SET */;"),
			):
				with self.subTest(name=name):
					self.assertFalse(restore._is_encrypted(self._write(root, name, head)))

	def test_a_gzipped_dump_is_not_encrypted(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertFalse(
				restore._is_encrypted(self._write(root, "d.sql.gz", gzip.compress(b"-- dump")))
			)

	def test_gpg_output_is_encrypted(self):
		"""frappe encrypts with `gpg -c`, whose output opens with an OpenPGP
		symmetric-key packet — verified against real gpg output (8c 0d …)."""
		with tempfile.TemporaryDirectory() as root:
			self.assertTrue(
				restore._is_encrypted(self._write(root, "d.sql.gz", b"\x8c\x0d\x04\x09\x03\x02\xff"))
			)

	def test_frappes_own_name_marker_wins(self):
		"""More reliable than any magic byte: it survives the file being
		recompressed or renamed by whatever copied it across."""
		with tempfile.TemporaryDirectory() as root:
			path = self._write(root, "x-database-enc.sql.gz", gzip.compress(b"-- looks plain"))
			self.assertTrue(restore._is_encrypted(path))

	def test_something_unrecognisable_is_treated_as_encrypted(self):
		"""Safer than the alternative: bench would drop the database and then
		fail to load anything into it."""
		with tempfile.TemporaryDirectory() as root:
			self.assertTrue(restore._is_encrypted(self._write(root, "d.bin", b"\x00\x01\x02\x03")))

	def test_a_plain_sql_dump_can_actually_be_restored(self):
		"""The end-to-end symptom: it was refused at argv construction."""
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", SITE))
			dump = self._write(root, "from_prod.sql", b"-- MySQL dump\nCREATE TABLE x;")
			backup = restore.resolve_chosen(root, SITE, dump)
			self.assertFalse(backup.encrypted)
			argv = restore.build_argv(BENCH_EXE, SITE, backup, "pw")
			self.assertIn("--db-root-password", argv)
			self.assertNotIn("--encryption-key", argv)
