# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The SSH configuration detector, built entirely against fixtures.

THERE IS NO SSHD ON THIS MACHINE. It is a WSL2 development box with no
openssh-server installed, so `sshd -T` cannot be run here and every path in
`sshd.py` is exercised against checked-in output instead. That is the same
position `ssh/parser.py` was written from, and the fixtures are what made it
correct before it ever met a real log. It still has to be confirmed on the
real server; what these tests establish is that the parsing and the judgement
are right, not that the collector's subprocess call works.

Three fixtures, each a real configuration shape:

  sshd_t_stock.txt      Ubuntu 24.04 as it ships — `PasswordAuthentication
                        yes`, `PermitRootLogin prohibit-password`, LogLevel
                        INFO. Calibration: what does an untouched server say?
  sshd_t_hardened.txt   The target state. MUST produce silence — a checker
                        that still complains about a correctly locked door is
                        one nobody keeps running.
  sshd_t_breached.txt   Every setting wrong at once, including the exact pair
                        that turns a host into the open proxy the real
                        incident was noticed as.
"""

import pathlib
import unittest

from server.security import sshd
from server.security import sshd_rules as rules

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _snapshot(name, matches=(), file_hashes=None):
	return sshd.Snapshot(
		effective=sshd.parse_effective((FIXTURES / f"sshd_t_{name}.txt").read_text()),
		match_blocks=tuple(matches),
		file_hashes=file_hashes or {},
	)


def _subjects(findings):
	return [f.subject for f in findings]


def _severities(findings):
	return {f.severity for f in findings}


class TestParsing(unittest.TestCase):
	def test_keys_are_lowercased_and_values_kept_verbatim(self):
		settings = sshd.parse_effective("PermitRootLogin prohibit-password\nloglevel VERBOSE\n")
		self.assertEqual(settings["permitrootlogin"], ["prohibit-password"])
		self.assertEqual(settings["loglevel"], ["VERBOSE"])

	def test_repeated_keys_are_kept_as_a_list(self):
		"""Flattening to the last value loses the second listen address.

		Which is how a host ends up listening somewhere nobody meant it to,
		with the monitoring reporting only the address they expected.
		"""
		settings = sshd.parse_effective("listenaddress 0.0.0.0:22\nlistenaddress [::]:22\n")
		self.assertEqual(len(settings["listenaddress"]), 2)

	def test_stock_fixture_parses_completely(self):
		settings = _snapshot("stock").effective
		self.assertGreater(len(settings), 30)
		self.assertEqual(settings["passwordauthentication"], ["yes"])


class TestMatchBlockParsing(unittest.TestCase):
	CONFIG = (FIXTURES / "sshd_config_with_match.txt").read_text()

	def test_finds_every_block(self):
		blocks = sshd.parse_match_blocks(self.CONFIG)
		self.assertEqual([b.criteria for b in blocks], ["Group deploy", "Address 10.0.0.0/8"])

	def test_settings_are_attributed_to_the_right_block(self):
		blocks = {b.criteria: b.settings for b in sshd.parse_match_blocks(self.CONFIG)}
		self.assertEqual(blocks["Group deploy"]["passwordauthentication"], "yes")
		self.assertEqual(blocks["Address 10.0.0.0/8"]["permitrootlogin"], "yes")

	def test_the_global_section_is_not_returned_as_a_block(self):
		"""Everything before the first Match is already covered by `sshd -T`.

		Returning it here would double-report every global setting, and this
		function exists only for what `sshd -T` cannot see.
		"""
		blocks = sshd.parse_match_blocks(self.CONFIG)
		self.assertNotIn("passwordauthentication", {k for b in blocks for k in b.settings if b.criteria == ""})
		self.assertTrue(all(b.criteria for b in blocks))

	def test_comments_do_not_become_settings(self):
		blocks = sshd.parse_match_blocks("Match User bob\n\t# PasswordAuthentication yes\n\tX11Forwarding no\n")
		self.assertEqual(blocks[0].settings, {"x11forwarding": "no"})


class TestCalibration(unittest.TestCase):
	"""The severity mix on each fixture, which is the whole design.

	The spec is explicit that an alerting system which cries wolf on day three
	is worse than none at all. Stock Ubuntu ships several settings that are
	dangerous-by-default, and calling all of them Critical would produce a
	server that alerts five times on the day it is installed.
	"""

	def test_a_hardened_server_produces_silence(self):
		findings = rules.judge(_snapshot("hardened"))
		self.assertEqual(_subjects(findings), [], "a correctly configured server must say nothing")

	def test_stock_ubuntu_raises_exactly_one_critical(self):
		"""And it is the right one — passwords are how the real breach happened."""
		findings = rules.judge(_snapshot("stock"))
		criticals = [f for f in findings if f.severity == rules.CRITICAL]
		self.assertEqual(len(criticals), 1)
		self.assertIn("passwords", criticals[0].subject.lower())

	def test_stock_default_root_login_is_not_critical(self):
		"""`prohibit-password` is the Ubuntu default and refuses passwords.

		Reporting the default as Critical is how a checker trains its reader
		to dismiss the category.
		"""
		findings = rules.judge(_snapshot("stock"))
		root = [f for f in findings if "Root can log in" in f.subject]
		self.assertEqual([f.severity for f in root], [rules.MEDIUM])

	def test_a_breached_configuration_lights_up(self):
		findings = rules.judge(_snapshot("breached"))
		self.assertGreaterEqual(len([f for f in findings if f.severity == rules.CRITICAL]), 3)
		self.assertIn(rules.HIGH, _severities(findings))


class TestTheWayIn(unittest.TestCase):
	def test_password_authentication_is_critical(self):
		findings = rules.judge_authentication(_snapshot("stock"))
		self.assertIn("SSH accepts passwords", _subjects(findings))

	def test_empty_passwords_are_critical(self):
		findings = rules.judge_authentication(_snapshot("breached"))
		empty = [f for f in findings if "empty" in f.subject]
		self.assertEqual([f.severity for f in empty], [rules.CRITICAL])

	def test_an_allow_list_silences_the_open_access_finding(self):
		self.assertNotIn(
			"Every account on the host can log in over SSH",
			_subjects(rules.judge_authentication(_snapshot("hardened"))),
		)


class TestTheMatchBlockBlindSpot(unittest.TestCase):
	"""The finding no tool reading only `sshd -T` can produce.

	A server whose effective configuration says `passwordauthentication no`,
	and which accepts passwords anyway for one group. `sshd -T` evaluates
	Match blocks against an empty connection, so its output is silent about
	this — the config file is the only place it is visible.
	"""

	def _hardened_with_matches(self):
		return _snapshot(
			"hardened",
			matches=sshd.parse_match_blocks((FIXTURES / "sshd_config_with_match.txt").read_text()),
		)

	def test_a_match_block_re_enabling_passwords_is_critical(self):
		findings = rules.judge_matches(self._hardened_with_matches())
		self.assertTrue(any("accepts passwords" in f.subject for f in findings))
		self.assertEqual(_severities(findings), {rules.CRITICAL})

	def test_the_finding_says_sshd_t_does_not_show_it(self):
		"""Otherwise the reader checks `sshd -T`, sees "no", and closes it."""
		findings = rules.judge_matches(self._hardened_with_matches())
		self.assertTrue(all("does NOT show this" in f.detail for f in findings))

	def test_a_match_block_agreeing_with_the_global_setting_is_not_a_finding(self):
		snapshot = _snapshot(
			"hardened", matches=[sshd.MatchBlock(criteria="User bob", settings={"passwordauthentication": "no"})]
		)
		self.assertEqual(rules.judge_matches(snapshot), [])


class TestTheProxy(unittest.TestCase):
	"""The half of the incident that had consequences.

	The intrusion was not noticed because somebody logged in. It was noticed
	because the address started carrying other people's traffic and the
	hosting provider complained.
	"""

	def test_forwarding_plus_gatewayports_is_judged_as_a_pair(self):
		findings = rules.judge_forwarding(_snapshot("breached"))
		proxy = [f for f in findings if "anywhere to anywhere" in f.subject]
		self.assertEqual([f.severity for f in proxy], [rules.HIGH])

	def test_forwarding_alone_is_only_recorded(self):
		"""It is the default and makes ordinary tunnelling work.

		Raising it on every stock server would bury the pair that matters.
		"""
		findings = rules.judge_forwarding(_snapshot("stock"))
		self.assertEqual([f.severity for f in findings], [rules.INFO])

	def test_a_host_with_forwarding_disabled_says_nothing(self):
		self.assertEqual(rules.judge_forwarding(_snapshot("hardened")), [])

	def test_permituserenvironment_is_flagged_as_code_execution(self):
		findings = rules.judge_forwarding(_snapshot("breached"))
		env = [f for f in findings if "environment variables" in f.subject]
		self.assertEqual([f.severity for f in env], [rules.HIGH])
		self.assertIn("LD_PRELOAD", env[0].detail)


class TestVisibility(unittest.TestCase):
	def test_quiet_logging_is_high_because_it_blinds_this_app(self):
		findings = rules.judge_logging(_snapshot("breached"))
		self.assertEqual([f.severity for f in findings], [rules.HIGH])

	def test_info_logging_costs_key_fingerprints_only(self):
		findings = rules.judge_logging(_snapshot("stock"))
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])
		self.assertIn("fingerprint", findings[0].subject.lower())

	def test_verbose_is_what_this_app_wants(self):
		self.assertEqual(rules.judge_logging(_snapshot("hardened")), [])


class TestCrypto(unittest.TestCase):
	def test_broken_algorithms_are_named_individually(self):
		findings = rules.judge_crypto(_snapshot("breached"))
		detail = " ".join(f.detail for f in findings)
		for algorithm in ("aes128-cbc", "3des-cbc", "hmac-md5", "diffie-hellman-group1-sha1"):
			self.assertIn(algorithm, detail)

	def test_modern_defaults_are_not_flagged(self):
		""""Not the newest" must not be a finding.

		A crypto check that fires on every default configuration is one that
		gets switched off, taking the real findings with it.
		"""
		self.assertEqual(rules.judge_crypto(_snapshot("hardened")), [])


class TestDrift(unittest.TestCase):
	def test_no_baseline_means_no_drift(self):
		"""The first scan has nothing to compare against.

		Reporting every file as new on day one is how a drift detector
		teaches its reader to ignore it.
		"""
		snapshot = _snapshot("hardened", file_hashes={"/etc/ssh/sshd_config": "a" * 64})
		self.assertEqual(rules.judge_drift({}, snapshot), [])

	def test_a_changed_file_is_reported(self):
		snapshot = _snapshot("hardened", file_hashes={"/etc/ssh/sshd_config": "b" * 64})
		findings = rules.judge_drift({"/etc/ssh/sshd_config": "a" * 64}, snapshot)
		self.assertEqual([f.severity for f in findings], [rules.HIGH])

	def test_a_new_file_in_the_include_directory_is_reported(self):
		"""The subtle one — nobody edits the file they would think to check.

		Ubuntu's `Include` sits at the TOP of sshd_config and sshd takes the
		FIRST value it sees for most keywords, so a dropped-in file overrides
		the main config without changing it.
		"""
		snapshot = _snapshot(
			"hardened",
			file_hashes={"/etc/ssh/sshd_config": "a" * 64, "/etc/ssh/sshd_config.d/99-x.conf": "c" * 64},
		)
		findings = rules.judge_drift({"/etc/ssh/sshd_config": "a" * 64}, snapshot)
		self.assertEqual(len(findings), 1)
		self.assertIn("new SSH configuration file appeared", findings[0].subject)

	def test_a_removed_hardening_file_is_reported(self):
		snapshot = _snapshot("hardened", file_hashes={"/etc/ssh/sshd_config": "a" * 64})
		findings = rules.judge_drift(
			{"/etc/ssh/sshd_config": "a" * 64, "/etc/ssh/sshd_config.d/99-hardening.conf": "d" * 64},
			snapshot,
		)
		self.assertIn("was removed", findings[0].subject)
		self.assertIn("defaults to yes", findings[0].detail)

	def test_only_hashes_are_ever_mentioned(self):
		"""The config names bastion hosts and account names; never store it.

		This asserts the finding text itself carries no configuration content
		— it is the part a collector, an email and a Slack channel all see.
		"""
		snapshot = _snapshot("hardened", file_hashes={"/etc/ssh/sshd_config": "b" * 64})
		findings = rules.judge_drift({"/etc/ssh/sshd_config": "a" * 64}, snapshot)
		for word in ("AllowUsers", "ListenAddress", "HostKey"):
			self.assertNotIn(word.lower(), findings[0].detail.lower())


class TestCoverage(unittest.TestCase):
	def test_being_unable_to_run_sshd_t_is_a_high_finding(self):
		"""Because no findings and no visibility look identical from outside."""
		snapshot = sshd.Snapshot(
			surfaces=(sshd.Surface("sshd", "sshd -T", False, "sshd is not installed", 0),)
		)
		findings = rules.judge_coverage(list(snapshot.surfaces))
		self.assertEqual([f.severity for f in findings], [rules.HIGH])
		self.assertIn("absence of evidence", findings[0].runbook)

	def test_unreadable_config_files_alone_are_a_partial_gap(self):
		surfaces = [sshd.Surface("sshd-config", "/etc/ssh/sshd_config", False, "denied", 0)]
		findings = rules.judge_coverage(surfaces)
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])
		self.assertIn("Match", findings[0].detail)

	def test_a_readable_host_reports_no_gap(self):
		surfaces = [sshd.Surface("sshd", "sshd -T", True, "", 40)]
		self.assertEqual(rules.judge_coverage(surfaces), [])

	def test_every_finding_carries_a_runbook(self):
		findings = rules.judge(_snapshot("breached"))
		self.assertTrue(findings)
		for finding in findings:
			with self.subTest(subject=finding.subject):
				self.assertTrue(finding.runbook.strip())
				self.assertNotEqual(finding.runbook.strip(), finding.detail.strip())


class TestUnreadableConfigIsNotJudged(unittest.TestCase):
	"""A host whose configuration could not be read must not be described.

	Every settings rule reaches for a value with a default. That is right when
	sshd did not mention a keyword and wrong when sshd was never asked, and the
	difference is invisible inside the rule. Running them anyway produced three
	findings about a configuration nobody had seen — and buried the one finding
	that was true.
	"""

	def _unreadable(self, **kwargs):
		return sshd.Snapshot(
			effective={},
			surfaces=(sshd.Surface("sshd", "sshd -T", False, "sshd is not installed", 0),),
			**kwargs,
		)

	def test_no_settings_findings_are_invented(self):
		findings = rules.judge(self._unreadable())
		self.assertEqual(
			_subjects(findings), ["The effective SSH configuration could not be read"]
		)

	def test_match_blocks_are_still_checked(self):
		"""The files are readable without root, and are a separate source.

		A Match block re-enabling passwords is visible even when `sshd -T`
		refuses to run, so losing one check must not cost the other.
		"""
		findings = rules.judge(
			self._unreadable(
				match_blocks=tuple(
					sshd.parse_match_blocks((FIXTURES / "sshd_config_with_match.txt").read_text())
				)
			)
		)
		self.assertTrue(any(f.severity == rules.CRITICAL for f in findings))

	def test_drift_is_still_checked(self):
		snapshot = self._unreadable(file_hashes={"/etc/ssh/sshd_config": "b" * 64})
		findings = rules.judge(snapshot, {"/etc/ssh/sshd_config": "a" * 64})
		self.assertTrue(any("changed" in f.subject for f in findings))
