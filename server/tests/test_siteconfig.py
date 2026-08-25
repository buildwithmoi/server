# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Site configuration reading and writing tests.

Two things carry real risk here and both are tested hard: the same file holds
the database password, so nothing secret may ever come back out of `read`; and
frappe reads these values with plain truthiness, so `"false"` reaching the file
as a string would silently mean the opposite of what was asked.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from server.bench import siteconfig as sc

SITE = "erp.example.com"

BASE = {
	"db_name": "_abc123",
	"db_password": "s3cret-do-not-leak",
	"encryption_key": "k3y-do-not-leak",
	"db_type": "mariadb",
	"developer_mode": 1,
}


def make_site(root: str, config: dict | None = None) -> str:
	directory = os.path.join(root, "sites", SITE)
	os.makedirs(directory, exist_ok=True)
	path = os.path.join(directory, "site_config.json")
	with open(path, "w") as handle:
		json.dump(BASE if config is None else config, handle)
	return path


class TestSecretDetection(unittest.TestCase):
	def test_known_secrets_are_secret(self):
		for key in ("db_password", "encryption_key", "mariadb_root_password", "admin_password"):
			with self.subTest(key=key):
				self.assertTrue(sc.is_secret(key))

	def test_unanticipated_secrets_are_caught_by_suffix(self):
		"""Redacted by default rather than leaked by omission."""
		for key in ("stripe_secret_key", "smtp_password", "github_token", "aws_credentials"):
			with self.subTest(key=key):
				self.assertTrue(sc.is_secret(key))

	def test_ordinary_keys_are_not_secret(self):
		for key in ("db_name", "host_name", "developer_mode", "installed_apps", "public_key"):
			with self.subTest(key=key):
				self.assertFalse(sc.is_secret(key))

	def test_matching_is_case_insensitive(self):
		self.assertTrue(sc.is_secret("DB_PASSWORD"))


class TestRead(unittest.TestCase):
	def test_no_secret_value_ever_comes_back(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			report = sc.read(root, SITE)
			blob = json.dumps(report)
			self.assertNotIn("s3cret-do-not-leak", blob)
			self.assertNotIn("k3y-do-not-leak", blob)

	def test_a_secret_is_reported_as_present(self):
		"""'Is an encryption key set' is a real question with a safe answer."""
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			row = next(v for v in sc.read(root, SITE)["values"] if v["key"] == "encryption_key")
			self.assertTrue(row["secret"])
			self.assertEqual(row["value"], sc.REDACTED)

	def test_ordinary_values_come_back_intact(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			row = next(v for v in sc.read(root, SITE)["values"] if v["key"] == "db_name")
			self.assertEqual(row["value"], "_abc123")

	def test_unset_settings_are_still_listed(self):
		"""The switch you came for must be on the page even if never set."""
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			row = next(e for e in sc.read(root, SITE)["editable"] if e["key"] == "maintenance_mode")
			self.assertFalse(row["present"])
			self.assertIs(row["effective"], False)

	def test_a_missing_file_is_reported_not_raised(self):
		with tempfile.TemporaryDirectory() as root:
			report = sc.read(root, SITE)
			self.assertFalse(report["exists"])
			self.assertEqual(report["values"], [])

	def test_malformed_json_is_reported_not_raised(self):
		with tempfile.TemporaryDirectory() as root:
			path = make_site(root)
			with open(path, "w") as handle:
				handle.write("{not json")
			report = sc.read(root, SITE)
			self.assertIsNotNone(report["error"])


class TestCoercion(unittest.TestCase):
	def test_false_as_a_string_becomes_a_real_false(self):
		"""A non-empty string is truthy; this is the whole reason coerce exists."""
		setting = sc.BY_KEY["maintenance_mode"]
		self.assertIs(sc.coerce(setting, "false"), False)
		self.assertIs(sc.coerce(setting, "0"), False)
		self.assertIs(sc.coerce(setting, "no"), False)

	def test_truthy_strings_become_true(self):
		setting = sc.BY_KEY["maintenance_mode"]
		for value in ("true", "1", "yes", "on", "TRUE"):
			with self.subTest(value=value):
				self.assertIs(sc.coerce(setting, value), True)

	def test_integers_are_validated(self):
		setting = sc.BY_KEY["max_file_size"]
		self.assertEqual(sc.coerce(setting, "1024"), 1024)
		with self.assertRaises(sc.ConfigRefused):
			sc.coerce(setting, "big")
		with self.assertRaises(sc.ConfigRefused):
			sc.coerce(setting, -1)

	def test_host_name_must_be_a_url(self):
		setting = sc.BY_KEY["host_name"]
		self.assertEqual(sc.coerce(setting, "https://erp.example.com"), "https://erp.example.com")
		for bad in ("erp.example.com", "ftp://x.com", "not a url"):
			with self.subTest(value=bad), self.assertRaises(sc.ConfigRefused):
				sc.coerce(setting, bad)


class TestWrite(unittest.TestCase):
	def _config(self, root: str) -> dict:
		with open(sc.config_path(root, SITE)) as handle:
			return json.load(handle)

	def test_a_boolean_lands_as_a_json_boolean(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"maintenance_mode": "true"})
			self.assertIs(self._config(root)["maintenance_mode"], True)

	def test_secrets_are_untouched_by_a_write(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"maintenance_mode": True})
			config = self._config(root)
			self.assertEqual(config["db_password"], "s3cret-do-not-leak")
			self.assertEqual(config["encryption_key"], "k3y-do-not-leak")

	def test_a_secret_cannot_be_written(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			with self.assertRaises(sc.ConfigRefused):
				sc.write(root, SITE, {"db_password": "new"})

	def test_an_unknown_key_is_refused(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			with self.assertRaises(sc.ConfigRefused):
				sc.write(root, SITE, {"arbitrary_thing": 1})

	def test_clearing_a_string_removes_the_key(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"host_name": "https://a.example.com"})
			sc.write(root, SITE, {"host_name": ""})
			self.assertNotIn("host_name", self._config(root))

	def test_other_keys_survive(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"maintenance_mode": True})
			self.assertEqual(self._config(root)["db_name"], "_abc123")

	def test_a_copy_is_taken_first(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			result = sc.write(root, SITE, {"maintenance_mode": True})
			self.assertTrue(os.path.isfile(result["backup"]))
			with open(result["backup"]) as handle:
				self.assertNotIn("maintenance_mode", json.load(handle))

	def test_no_temp_file_is_left_behind(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"maintenance_mode": True})
			directory = os.path.dirname(sc.config_path(root, SITE))
			self.assertEqual([f for f in os.listdir(directory) if f.startswith(".site_config-")], [])

	def test_a_refused_write_changes_nothing(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			before = self._config(root)
			with self.assertRaises(sc.ConfigRefused):
				sc.write(root, SITE, {"maintenance_mode": True, "db_password": "new"})
			self.assertEqual(self._config(root), before)

	def test_writing_to_a_missing_file_is_refused(self):
		with tempfile.TemporaryDirectory() as root:
			with self.assertRaises(sc.ConfigRefused):
				sc.write(root, SITE, {"maintenance_mode": True})

	def test_the_result_is_valid_json_frappe_can_read(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root)
			sc.write(root, SITE, {"maintenance_mode": True, "max_file_size": "2048"})
			config = self._config(root)
			self.assertIs(config["maintenance_mode"], True)
			self.assertEqual(config["max_file_size"], 2048)


if __name__ == "__main__":
	unittest.main()


class TestOutputScrubbing(unittest.TestCase):
	"""Command output is stored in the database and rendered in the interface.

	`bench show-config` prints db_password and encryption_key in plain text, so
	one catalogued READ-ONLY command was enough to write both into a log this
	app displays — undoing every bit of redaction in the config editor. Applied
	to output rather than to a list of known-bad commands, because the next
	command that prints a credential will not be one anybody predicted.
	"""

	def test_the_table_format_bench_actually_prints(self):
		line = "| db_password                  | verysecret123                                |"
		scrubbed = sc.scrub(line)
		self.assertNotIn("verysecret123", scrubbed)
		self.assertIn("db_password", scrubbed)
		self.assertIn(sc.REDACTED, scrubbed)

	def test_encryption_keys_are_scrubbed(self):
		line = "| encryption_key               | lVftSfJftuNfy-tE8CwIFOwdBQTpbZSL= |"
		self.assertNotIn("lVftSfJftuNfy", sc.scrub(line))

	def test_json_and_key_value_forms_too(self):
		self.assertNotIn("abc123", sc.scrub('"encryption_key": "abc123",'))
		self.assertNotIn("hunter2", sc.scrub("mariadb_root_password=hunter2"))

	def test_ordinary_output_is_untouched(self):
		for line in (
			"| db_name                      | _c817a1c9040319df                            |",
			"| gunicorn_workers             | 17                                           |",
			"Receiving objects:  43% (1234/2870)",
			"$ bench --site a.local migrate",
		):
			with self.subTest(line=line):
				self.assertEqual(sc.scrub(line), line)

	def test_an_unanticipated_secret_key_is_scrubbed_too(self):
		self.assertNotIn("sk_live_abc", sc.scrub("| stripe_secret_key | sk_live_abc |"))


class TestNestedRedaction(unittest.TestCase):
	"""site_config grows structures, not just flat keys.

	An smtp block with a `password`, a `domains` list whose entries carry
	certificate keys — the top-level check returned all of those verbatim,
	which is the exact failure this redaction exists to prevent, one level down.
	"""

	def _read(self, config):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, config)
			return json.dumps(sc.read(root, SITE))

	def test_a_secret_inside_a_dict_is_redacted(self):
		blob = self._read({"smtp": {"password": "MARKER-NESTED", "host": "mail.example.com"}})
		self.assertNotIn("MARKER-NESTED", blob)
		self.assertIn("mail.example.com", blob)

	def test_a_secret_inside_a_list_is_redacted(self):
		blob = self._read({"domains": [{"ssl_certificate_key": "MARKER-LIST", "domain": "a.com"}]})
		self.assertNotIn("MARKER-LIST", blob)
		self.assertIn("a.com", blob)

	def test_deeply_nested_secrets_are_redacted(self):
		blob = self._read({"a": {"b": {"c": {"api_token": "MARKER-DEEP"}}}})
		self.assertNotIn("MARKER-DEEP", blob)

	def test_bare_credential_names_are_secret(self):
		""""password" does not end in "_password", so the suffix list missed it
		— and bare names are exactly how a credential is spelled inside a
		nested block."""
		for key in ("password", "passwd", "secret", "token", "private_key"):
			with self.subTest(key=key):
				self.assertTrue(sc.is_secret(key))

	def test_ordinary_nested_values_survive(self):
		blob = self._read({"smtp": {"host": "mail.example.com", "port": 587}})
		self.assertIn("mail.example.com", blob)
		self.assertIn("587", blob)


class TestUnsettingFields(unittest.TestCase):
	def test_an_emptied_integer_field_means_unset(self):
		"""It meant "invalid" — so a number could never be unset at all, and
		clearing the field returned "must be a whole number"."""
		with tempfile.TemporaryDirectory() as root:
			make_site(root, {"max_file_size": 1024, "db_name": "x"})
			sc.write(root, SITE, {"max_file_size": ""})
			with open(sc.config_path(root, SITE)) as handle:
				config = json.load(handle)
			self.assertNotIn("max_file_size", config)
			self.assertEqual(config["db_name"], "x")

	def test_a_real_number_still_validates(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, {"db_name": "x"})
			sc.write(root, SITE, {"max_file_size": "2048"})
			with open(sc.config_path(root, SITE)) as handle:
				self.assertEqual(json.load(handle)["max_file_size"], 2048)

	def test_junk_is_still_refused(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, {"db_name": "x"})
			with self.assertRaises(sc.ConfigRefused):
				sc.write(root, SITE, {"max_file_size": "big"})
