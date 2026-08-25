# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading what a backup needs, before restoring it.

The failure this prevents is the one that looks like a success: restore a
database that references an app the bench does not have, and the site comes up
with every DocType belonging to that app silently gone. It surfaces days later
as import errors nobody connects back to the restore.

Frappe-free — the dump is just a file, and these run against fixtures written
to a temp directory.
"""

from __future__ import annotations

import gzip
import os
import tempfile
import unittest

from server.bench import inspect

COLUMNS = (
	"name",
	"creation",
	"modified",
	"modified_by",
	"owner",
	"docstatus",
	"idx",
	"app_name",
	"app_version",
	"git_branch",
	"has_setup_wizard",
	"is_setup_complete",
	"parent",
	"parentfield",
	"parenttype",
)


def make_dump(path: str, apps, columns=COLUMNS, compress=True, prefix=b"", suffix=b"") -> str:
	body = ",\n  ".join(f"`{name}` varchar(140) DEFAULT NULL" for name in columns)
	rows = []
	for index, (app, version, branch) in enumerate(apps, start=1):
		values = {
			"name": f"row{index}",
			"creation": "2026-01-01 00:00:00",
			"modified": "2026-01-01 00:00:00",
			"modified_by": "Administrator",
			"owner": "Administrator",
			"docstatus": "0",
			"idx": str(index),
			"app_name": app,
			"app_version": version,
			"git_branch": branch,
			"has_setup_wizard": "0",
			"is_setup_complete": "0",
			"parent": "Installed Applications",
			"parentfield": "installed_applications",
			"parenttype": "Installed Applications",
		}
		rows.append("(" + ",".join(f"'{values.get(name, '')}'" for name in columns) + ")")

	sql = (
		prefix
		+ f"CREATE TABLE `{inspect.APPS_TABLE}` (\n  {body}\n) ENGINE=InnoDB;\n".encode()
		+ f"INSERT INTO `{inspect.APPS_TABLE}` VALUES\n  " .encode()
		+ (",\n  ".join(rows) + ";\n").encode()
		+ suffix
	)
	with open(path, "wb") as handle:
		handle.write(gzip.compress(sql) if compress else sql)
	return path


class TestReadingApps(unittest.TestCase):
	def test_names_versions_and_branches_are_read(self):
		with tempfile.TemporaryDirectory() as root:
			path = make_dump(
				os.path.join(root, "d.sql.gz"),
				[("frappe", "16.31.0", "version-16"), ("hrms", "16.0.1", "main")],
			)
			apps = {a.app_name: a for a in inspect.read_apps(path).apps}

			self.assertEqual(set(apps), {"frappe", "hrms"})
			self.assertEqual(apps["hrms"].git_branch, "main")
			self.assertEqual(apps["frappe"].app_version, "16.31.0")

	def test_an_uncompressed_dump_is_read_too(self):
		with tempfile.TemporaryDirectory() as root:
			path = make_dump(
				os.path.join(root, "d.sql"), [("frappe", "16.0.0", "main")], compress=False
			)
			self.assertEqual([a.app_name for a in inspect.read_apps(path).apps], ["frappe"])

	def test_column_order_is_taken_from_the_dump_not_assumed(self):
		"""frappe has added columns to this table before.

		A hardcoded index would quietly start reporting the version as the
		branch, which is worse than reporting nothing.
		"""
		shuffled = ("name", "app_version", "git_branch", "app_name", "idx")
		with tempfile.TemporaryDirectory() as root:
			path = make_dump(
				os.path.join(root, "d.sql.gz"), [("hrms", "16.0.1", "develop")], columns=shuffled
			)
			app = inspect.read_apps(path).apps[0]
			self.assertEqual(app.app_name, "hrms")
			self.assertEqual(app.git_branch, "develop")
			self.assertEqual(app.app_version, "16.0.1")

	def test_the_table_is_found_after_a_lot_of_other_data(self):
		with tempfile.TemporaryDirectory() as root:
			noise = b"-- unrelated dump content\n" * 200_000
			path = make_dump(
				os.path.join(root, "d.sql.gz"), [("frappe", "16.0.0", "main")], prefix=noise
			)
			self.assertEqual([a.app_name for a in inspect.read_apps(path).apps], ["frappe"])

	def test_a_dump_without_the_table_says_so(self):
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "d.sql.gz")
			with open(path, "wb") as handle:
				handle.write(gzip.compress(b"CREATE TABLE `tabUser` (`name` varchar(140));\n"))
			contents = inspect.read_apps(path)
			self.assertEqual(contents.apps, [])
			self.assertIn("installed-application", contents.error)

	def test_an_encrypted_dump_reports_rather_than_raises(self):
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "d.sql.gz")
			with open(path, "wb") as handle:
				handle.write(b"\x8c\x0d\x04\x09\x03\x02" + os.urandom(256))
			contents = inspect.read_apps(path)
			self.assertEqual(contents.apps, [])
			self.assertTrue(contents.error)

	def test_a_missing_file_reports_rather_than_raises(self):
		contents = inspect.read_apps("/nonexistent-dump-for-tests.sql.gz")
		self.assertTrue(contents.error)
		self.assertEqual(contents.apps, [])


class TestValueParsing(unittest.TestCase):
	def test_a_comma_inside_a_value_does_not_shift_columns(self):
		"""A naive split moves every column after the first comma."""
		values = inspect._split_row("'a','hello, world','c'")
		self.assertEqual(values, ["a", "hello, world", "c"])

	def test_escaped_quotes_survive(self):
		self.assertEqual(inspect._split_row(r"'it\'s','b'"), ["it's", "b"])
		self.assertEqual(inspect._split_row("'it''s','b'"), ["it's", "b"])

	def test_null_becomes_empty(self):
		self.assertEqual(inspect._split_row("'a',NULL,'c'"), ["a", "", "c"])

	def test_unquoted_numbers_are_kept(self):
		self.assertEqual(inspect._split_row("'a',0,42"), ["a", "0", "42"])


class TestComparingAgainstABench(unittest.TestCase):
	def _contents(self, apps):
		return inspect.BackupContents(
			apps=[inspect.BackupApp(app_name=a, git_branch=b) for a, b in apps]
		)

	def test_missing_apps_are_named(self):
		compared = inspect.compare(
			self._contents([("frappe", "version-16"), ("hrms", "main")]), {"frappe": "version-16"}
		)
		self.assertEqual(compared.as_dict()["missing"], ["hrms"])

	def test_a_present_app_on_the_wrong_branch_is_flagged_but_not_missing(self):
		compared = inspect.compare(
			self._contents([("erpnext", "version-16")]), {"erpnext": "version-15"}
		)
		app = compared.apps[0]
		self.assertTrue(app.present)
		self.assertFalse(app.branch_matches)
		self.assertIn("version-15", app.note)
		self.assertEqual(compared.as_dict()["missing"], [])

	def test_a_matching_branch_is_ready(self):
		compared = inspect.compare(self._contents([("frappe", "version-16")]), {"frappe": "version-16"})
		self.assertEqual(compared.apps[0].note, "Ready.")

	def test_an_unknown_branch_on_either_side_is_not_a_mismatch(self):
		"""Absence of information is not evidence of a problem.

		A backup with no recorded branch, or a bench app whose branch could not
		be read, must not be reported as a conflict — that is noise on top of a
		screen the operator is meant to act on.
		"""
		cases = (
			("", "version-16"),  # backup does not say
			("version-16", ""),  # bench does not say
			("", ""),  # neither says
		)
		for backup_branch, installed_branch in cases:
			with self.subTest(backup=backup_branch, installed=installed_branch):
				compared = inspect.compare(
					self._contents([("frappe", backup_branch)]), {"frappe": installed_branch}
				)
				self.assertTrue(compared.apps[0].branch_matches)


class TestSiteConfigSnapshot(unittest.TestCase):
	def test_only_key_names_are_returned(self):
		"""The snapshot holds the database password and the encryption key, and
		this is rendered in a browser."""
		import json

		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "c.json")
			with open(path, "w") as handle:
				json.dump({"db_name": "abc", "db_password": "MARKER", "encryption_key": "MARKER2"}, handle)

			keys = inspect.read_site_config(path)
			self.assertEqual(keys, ["db_name", "db_password", "encryption_key"])
			self.assertNotIn("MARKER", json.dumps(keys))

	def test_a_missing_snapshot_is_not_an_error(self):
		self.assertEqual(inspect.read_site_config(None), [])
		self.assertEqual(inspect.read_site_config("/nonexistent.json"), [])


if __name__ == "__main__":
	unittest.main()


class TestColumnParsingIsFormatIndependent(unittest.TestCase):
	"""mysqldump writes one column per line; other tools do not.

	Requiring a line start meant a `--compact` dump reported no apps at all —
	the worst possible answer, because "no apps" reads as "nothing to install"
	rather than "could not tell".
	"""

	BODY_ONE_LINE = (
		"`name` varchar(140), `app_name` varchar(140), "
		"`app_version` varchar(140), `git_branch` varchar(140)"
	)

	def test_columns_on_a_single_line_are_found(self):
		self.assertEqual(
			inspect._columns_of(self.BODY_ONE_LINE),
			["name", "app_name", "app_version", "git_branch"],
		)

	def test_index_clauses_are_not_mistaken_for_columns(self):
		body = (
			"  `name` varchar(140) NOT NULL,\n"
			"  `app_name` varchar(140) DEFAULT NULL,\n"
			"  PRIMARY KEY (`name`),\n"
			"  KEY `parent` (`parent`)\n"
		)
		self.assertEqual(inspect._columns_of(body), ["name", "app_name"])

	def test_a_one_line_dump_reports_its_apps(self):
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "d.sql.gz")
			sql = (
				f"CREATE TABLE `{inspect.APPS_TABLE}` ({self.BODY_ONE_LINE}) ENGINE=InnoDB;\n"
				f"INSERT INTO `{inspect.APPS_TABLE}` VALUES "
				"('a','frappe','16.31.0','version-16'),('b','hrms','16.0.1','main');\n"
			).encode()
			with open(path, "wb") as handle:
				handle.write(gzip.compress(sql))

			apps = {a.app_name: a.git_branch for a in inspect.read_apps(path).apps}
			self.assertEqual(apps, {"frappe": "version-16", "hrms": "main"})


class TestEncryptedDumpsAreRefusedNotScanned(unittest.TestCase):
	"""Branching on the gzip magic alone let a gpg-encrypted dump through to a
	raw read, and the scan then chewed through up to 4 GiB of binary looking
	for a CREATE TABLE that cannot exist — inside a synchronous web request,
	holding a worker for minutes and then reporting "no installed-application
	table found", which is true and completely misleading."""

	def test_gpg_output_is_refused_immediately(self):
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "d.sql.gz")
			with open(path, "wb") as handle:
				handle.write(b"\x8c\x0d\x04\x09" + os.urandom(2_000_000))

			contents = inspect.read_apps(path)
			self.assertTrue(contents.encrypted)
			self.assertEqual(contents.scanned_bytes, 0, "it scanned an encrypted dump")
			self.assertIn("encrypted", contents.error)

	def test_frappes_own_enc_marker_is_enough(self):
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "x-database-enc.sql.gz")
			with open(path, "wb") as handle:
				handle.write(gzip.compress(b"-- looks like a plain dump"))
			self.assertTrue(inspect.read_apps(path).encrypted)

	def test_the_message_says_restoring_still_works(self):
		"""Not being able to LIST the apps is not the same as not being able to
		restore — saying so keeps the operator from thinking they are stuck."""
		with tempfile.TemporaryDirectory() as root:
			path = os.path.join(root, "d.sql.gz")
			with open(path, "wb") as handle:
				handle.write(b"\x8c\x0d\x04\x09")
			self.assertIn("Restoring it still works", inspect.read_apps(path).error)

	def test_a_plain_dump_is_still_scanned(self):
		with tempfile.TemporaryDirectory() as root:
			path = make_dump(os.path.join(root, "d.sql.gz"), [("frappe", "16.0.0", "main")])
			contents = inspect.read_apps(path)
			self.assertFalse(contents.encrypted)
			self.assertEqual([a.app_name for a in contents.apps], ["frappe"])
