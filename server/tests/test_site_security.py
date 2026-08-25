# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The security state of the application, not the machine under it.

The finding that prompted this module is real and was found on this bench:
frappe writes a copy of the site configuration beside every backup, containing
`db_password` and `encryption_key` in plain text at mode 0644, in a
world-traversable directory. The encryption key decrypts every `Password`
field in the site — which in this app means the database root password used
for restores and the token used to forward findings off the box.

The tests below build real files in a temporary directory with real modes,
because the whole check is about permissions and asserting on a mocked stat
would prove nothing.
"""

import json
import os
import stat
import tempfile
import unittest

from server.security import site
from server.security import site_rules as rules


def _config(path, mode, **values):
	with open(path, "w") as handle:
		json.dump(values, handle)
	os.chmod(path, mode)
	return path


def _subjects(findings):
	return [f.subject for f in findings]


def _severities(findings):
	return {f.severity for f in findings}


class TestReadingConfigFiles(unittest.TestCase):
	def test_secret_keys_are_named_but_values_never_kept(self):
		"""The module must describe the exposure without becoming it.

		A security scanner that helpfully collects every password into one
		place is the single richest target on the estate, which the spec
		explicitly forbids.
		"""
		with tempfile.TemporaryDirectory() as tmp:
			path = _config(
				os.path.join(tmp, "site_config.json"),
				0o644,
				db_password="hunter2",
				encryption_key="AAAA",
				db_name="_abc",
			)
			described = site.read_config_file(path)

		self.assertEqual(described.secret_keys, ("db_password", "encryption_key"))
		flat = json.dumps(described.as_dict())
		self.assertNotIn("hunter2", flat)
		self.assertNotIn("AAAA", flat)

	def test_mode_and_readability_are_recorded_accurately(self):
		with tempfile.TemporaryDirectory() as tmp:
			path = _config(os.path.join(tmp, "c.json"), 0o600, db_password="x")
			described = site.read_config_file(path)
			self.assertEqual(described.mode, "0600")
			self.assertFalse(described.world_readable)
			self.assertFalse(described.group_readable)

	def test_a_locked_down_file_does_not_expose_secrets(self):
		with tempfile.TemporaryDirectory() as tmp:
			path = _config(os.path.join(tmp, "c.json"), 0o600, db_password="x")
			self.assertFalse(site.read_config_file(path).exposes_secrets)

	def test_a_file_with_no_secrets_is_not_an_exposure(self):
		with tempfile.TemporaryDirectory() as tmp:
			path = _config(os.path.join(tmp, "c.json"), 0o644, webserver_port=8000)
			described = site.read_config_file(path)
			self.assertEqual(described.secret_keys, ())
			self.assertFalse(described.exposes_secrets)

	def test_unreadable_or_malformed_files_return_none(self):
		with tempfile.TemporaryDirectory() as tmp:
			path = os.path.join(tmp, "broken.json")
			with open(path, "w") as handle:
				handle.write("{not json")
			self.assertIsNone(site.read_config_file(path))
			self.assertIsNone(site.read_config_file(os.path.join(tmp, "absent.json")))


class TestPathTraversal(unittest.TestCase):
	"""Mode 0644 inside a 0700 directory is not exposed.

	Reporting it as exposed would be a false alarm on a correctly locked-down
	bench, and a check that cries wolf about a fix somebody already applied is
	one they stop believing.
	"""

	def test_a_private_parent_directory_protects_the_file(self):
		with tempfile.TemporaryDirectory() as tmp:
			inner = os.path.join(tmp, "private")
			os.mkdir(inner, 0o700)
			path = _config(os.path.join(inner, "c.json"), 0o644, db_password="x")
			described = site.read_config_file(path)
			self.assertTrue(described.world_readable, "the file itself is still 0644")
			self.assertFalse(described.path_traversable, "but nobody can walk down to it")

	def test_a_traversable_parent_leaves_it_exposed(self):
		with tempfile.TemporaryDirectory() as tmp:
			inner = os.path.join(tmp, "open")
			os.mkdir(inner, 0o755)
			os.chmod(tmp, 0o755)
			path = _config(os.path.join(inner, "c.json"), 0o644, db_password="x")
			described = site.read_config_file(path)
			self.assertTrue(described.exposes_secrets)
			self.assertTrue(described.path_traversable)


class TestExposureRules(unittest.TestCase):
	def _file(self, path="/b/sites/x/site_config.json", mode="0644", **kwargs):
		defaults = {
			"owner": "patoo",
			"world_readable": mode[-1] in "4567",
			"group_readable": mode[-2] in "4567",
			"secret_keys": ("db_password", "encryption_key"),
			"path_traversable": True,
		}
		defaults.update(kwargs)
		return site.ConfigFile(path=path, mode=mode, **defaults)

	# ------------------------------------------------------------------

	def test_world_readable_credentials_are_critical(self):
		findings = rules.judge_config_exposure([self._file()])
		self.assertEqual([f.severity for f in findings], [rules.CRITICAL])

	def test_the_finding_explains_why_the_encryption_key_is_the_worst_part(self):
		"""db_password reaches the database. encryption_key reaches everything.

		A reader who does not know that treats this as "tighten a file mode
		when convenient".
		"""
		finding = rules.judge_config_exposure([self._file()])[0]
		self.assertIn("encryption_key", finding.detail)
		self.assertIn("every stored password", finding.detail)

	def test_the_runbook_says_the_directory_must_be_fixed_too(self):
		"""Otherwise the next backup recreates the exposure.

		Fixing the files alone fixes it until tomorrow, which is the kind of
		half-fix that makes the alert come back and get muted.
		"""
		finding = rules.judge_config_exposure([self._file()])[0]
		self.assertIn("700", finding.runbook)
		self.assertIn("next backup", finding.runbook)

	def test_group_readable_only_is_high_not_critical(self):
		findings = rules.judge_config_exposure(
			[self._file(mode="0640", world_readable=False, group_readable=True)]
		)
		self.assertEqual([f.severity for f in findings], [rules.HIGH])

	def test_a_writable_config_is_reported_separately(self):
		"""Reading it yields the credentials; writing it picks the database."""
		findings = rules.judge_config_exposure([self._file(mode="0664")])
		self.assertIn(rules.CRITICAL, _severities(findings))
		self.assertTrue(any("WRITTEN" in f.subject for f in findings))

	def test_hundreds_of_sidecars_produce_one_finding_not_hundreds(self):
		"""A year-old bench has a sidecar per backup ever taken.

		Three hundred identical Criticals is the same as none.
		"""
		many = [self._file(path=f"/b/sites/x/private/backups/{n}-site_config_backup.json") for n in range(300)]
		findings = rules.judge_config_exposure(many)
		self.assertEqual(len(findings), 1)
		self.assertIn("300", findings[0].subject)

	def test_a_protected_file_raises_nothing(self):
		findings = rules.judge_config_exposure(
			[self._file(mode="0600", world_readable=False, group_readable=False)]
		)
		self.assertEqual(findings, [])

	def test_an_untraversable_path_raises_nothing(self):
		findings = rules.judge_config_exposure([self._file(path_traversable=False)])
		self.assertEqual(findings, [])


class TestSettingRules(unittest.TestCase):
	def _live(self, **settings):
		return site.ConfigFile(
			path="/b/sites/x/site_config.json",
			mode="0600",
			owner="patoo",
			world_readable=False,
			group_readable=False,
			settings=settings,
		)

	def test_developer_mode_names_this_apps_own_guest_endpoint(self):
		"""Because it is one of the things developer mode switches on.

		`get_context_for_dev` serves boot data without a session by design,
		and is safe only because developer mode is normally off.
		"""
		findings = rules.judge_settings([self._live(developer_mode=1)])
		self.assertEqual([f.severity for f in findings], [rules.HIGH])
		self.assertIn("get_context_for_dev", findings[0].detail)

	def test_allow_tests_is_flagged_as_data_destruction(self):
		findings = rules.judge_settings([self._live(allow_tests=True)])
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])

	def test_backup_sidecars_are_not_judged_for_settings(self):
		"""They record what was true when the backup was taken.

		Alerting on history is how a check becomes permanent noise — and a
		bench keeps one sidecar per backup forever.
		"""
		sidecar = site.ConfigFile(
			path="/b/sites/x/private/backups/2026-site_config_backup.json",
			mode="0600",
			owner="patoo",
			world_readable=False,
			group_readable=False,
			settings={"developer_mode": 1},
		)
		self.assertEqual(rules.judge_settings([sidecar]), [])

	def test_a_production_config_raises_nothing(self):
		self.assertEqual(rules.judge_settings([self._live(developer_mode=0)]), [])


class TestBackupRules(unittest.TestCase):
	def test_no_backups_is_high(self):
		findings = rules.judge_backups([site.BackupState(site="x", count=0)])
		self.assertEqual([f.severity for f in findings], [rules.HIGH])

	def test_a_stale_backup_is_measured_by_age_not_count(self):
		"""A failing backup job leaves the old files in place.

		So the directory looks healthy and the contents are stale, and
		counting files reports success right up until the restore.
		"""
		findings = rules.judge_backups(
			[site.BackupState(site="x", count=40, newest_age_hours=120, newest_has_files=True)]
		)
		self.assertTrue(any("days old" in f.subject for f in findings))

	def test_a_recent_complete_backup_raises_nothing(self):
		findings = rules.judge_backups(
			[site.BackupState(site="x", count=5, newest_age_hours=2, newest_has_files=True)]
		)
		self.assertEqual(findings, [])

	def test_a_database_only_backup_is_reported(self):
		findings = rules.judge_backups(
			[site.BackupState(site="x", count=5, newest_age_hours=2, newest_has_files=False)]
		)
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])

	def test_a_missed_run_within_tolerance_is_not_an_alert(self):
		findings = rules.judge_backups(
			[site.BackupState(site="x", count=5, newest_age_hours=30, newest_has_files=True)]
		)
		self.assertEqual(findings, [])


class TestAccountRules(unittest.TestCase):
	def test_a_small_admin_team_is_not_a_finding(self):
		self.assertEqual(rules.judge_accounts({"system_managers": ["a", "b"]}), [])

	def test_a_large_one_is(self):
		findings = rules.judge_accounts({"system_managers": [f"u{n}" for n in range(9)]})
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])

	def test_dormant_enabled_accounts_are_reported(self):
		findings = rules.judge_accounts({"enabled_never_logged_in": ["stale@example.com"]})
		self.assertTrue(any("never logged in" in f.subject for f in findings))

	def test_administrator_with_a_password_is_reported(self):
		findings = rules.judge_accounts(
			{"administrator_enabled": True, "administrator_has_password": True}
		)
		self.assertTrue(any("Administrator" in f.subject for f in findings))

	def test_no_account_data_produces_no_guesses(self):
		"""An empty inventory means the query failed, not that nobody exists."""
		self.assertEqual(rules.judge_accounts({}), [])


class TestAgainstThisBench(unittest.TestCase):
	"""The strongest check available: run it on the real thing.

	If a rule is written too broadly, a working bench says so immediately.
	"""

	BENCH = "/home/patoo/fb-16-server"

	def setUp(self):
		if not os.path.isdir(os.path.join(self.BENCH, "sites")):
			self.skipTest("not running inside the bench")

	def test_the_collector_reads_this_bench_without_raising(self):
		snapshot = site.collect(self.BENCH, ["local.16.server"])
		self.assertTrue(snapshot.configs)
		self.assertTrue(all(s.readable for s in snapshot.surfaces))

	def test_it_finds_the_real_credential_exposure(self):
		"""This bench genuinely has it, which is why the module exists."""
		snapshot = site.collect(self.BENCH, ["local.16.server"])
		exposed = [c for c in snapshot.configs if c.exposes_secrets]
		self.assertTrue(exposed, "expected world-readable site configs on this bench")
		self.assertTrue(any("encryption_key" in c.secret_keys for c in exposed))

	def test_no_secret_value_reaches_a_finding(self):
		"""The findings travel off the box, so this is the one that matters.

		A collector, an email and a Slack channel all see this text.
		"""
		snapshot = site.collect(self.BENCH, ["local.16.server"])
		secrets = set()
		for path in (os.path.join(self.BENCH, "sites", "local.16.server", "site_config.json"),):
			with open(path) as handle:
				for key, value in json.load(handle).items():
					if key in ("db_password", "encryption_key"):
						secrets.add(str(value))

		blob = " ".join(f"{f.subject} {f.detail} {f.runbook}" for f in rules.judge(snapshot))
		for secret in secrets:
			self.assertNotIn(secret, blob)
