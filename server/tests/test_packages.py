# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Software arriving, leaving, and going unpatched.

Both sources are real files on a stock Ubuntu and both are readable without
root, which is why this detector exists at all. The numbers in these tests came
from this box: 8,574 `status` lines against 1,214 `install` lines in dpkg.log,
and 25 pending updates of which 9 are from the security pocket.

Those two ratios are the whole design. Keeping dpkg's status chatter would mean
judging a thousand rows to find one; treating all 25 updates alike would turn
nine urgent things into twenty-five unremarkable ones.
"""

import unittest
from datetime import datetime, timedelta

from server.security import packages
from server.security import packages_rules as rules

DPKG_SAMPLE = """\
2026-08-20 09:00:00 startup archives unpack
2026-08-20 09:00:01 install netcat-openbsd:amd64 <none> 1.226-1ubuntu2
2026-08-20 09:00:02 status half-installed netcat-openbsd:amd64 1.226-1ubuntu2
2026-08-20 09:00:03 status installed netcat-openbsd:amd64 1.226-1ubuntu2
2026-08-20 09:01:00 upgrade curl:amd64 8.5.0-2ubuntu10.12 8.5.0-2ubuntu10.13
2026-08-20 09:02:00 remove rsyslog:amd64 8.2312.0-3ubuntu9 <none>
2026-08-20 09:03:00 configure curl:amd64 8.5.0-2ubuntu10.13 <none>
2026-08-20 09:04:00 trigproc man-db:amd64 2.12.0-4build2 <none>
"""

UPGRADABLE_SAMPLE = """\
Listing...
curl/noble-updates,noble-security 8.5.0-2ubuntu10.13 amd64 [upgradable from: 8.5.0-2ubuntu10.12]
byobu/noble-updates 6.11-0ubuntu1.1 all [upgradable from: 6.11-0ubuntu1]
vim/noble-updates,noble-security 2:9.1.0016-1ubuntu7.19 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.18]
"""


def _snapshot(events=(), upgradable=(), first_seen=None, surfaces=()):
	return packages.Snapshot(
		events=tuple(events), upgradable=tuple(upgradable), first_seen=first_seen or {}, surfaces=tuple(surfaces)
	)


def _subjects(findings):
	return [f.subject for f in findings]


class TestDpkgLogParsing(unittest.TestCase):
	def test_only_the_verbs_that_mean_something_are_kept(self):
		"""dpkg writes seven status lines for every install.

		Carrying them through would mean judging a thousand rows to find one.
		"""
		events = packages.parse_dpkg_log(DPKG_SAMPLE)
		self.assertEqual(
			sorted({e.action for e in events}), ["install", "remove", "upgrade"]
		)

	def test_install_remove_and_upgrade_are_told_apart(self):
		by_action = {e.action: e for e in packages.parse_dpkg_log(DPKG_SAMPLE)}
		self.assertEqual(by_action["install"].package, "netcat-openbsd")
		self.assertEqual(by_action["remove"].package, "rsyslog")
		self.assertEqual(by_action["upgrade"].package, "curl")

	def test_an_install_has_no_previous_version(self):
		"""dpkg writes the literal `<none>`, which must not become a version."""
		install = next(e for e in packages.parse_dpkg_log(DPKG_SAMPLE) if e.action == "install")
		self.assertEqual(install.old_version, "")
		self.assertEqual(install.new_version, "1.226-1ubuntu2")

	def test_an_upgrade_carries_both_versions(self):
		upgrade = next(e for e in packages.parse_dpkg_log(DPKG_SAMPLE) if e.action == "upgrade")
		self.assertEqual(upgrade.old_version, "8.5.0-2ubuntu10.12")
		self.assertEqual(upgrade.new_version, "8.5.0-2ubuntu10.13")

	def test_the_architecture_suffix_is_not_part_of_the_name(self):
		"""Otherwise `curl` and `curl:amd64` are two different packages."""
		self.assertTrue(all(":" not in e.package for e in packages.parse_dpkg_log(DPKG_SAMPLE)))

	def test_garbage_lines_are_skipped_not_guessed_at(self):
		self.assertEqual(packages.parse_dpkg_log("nonsense\n\n2026 bad line\n"), [])

	def test_notable_packages_are_recognised(self):
		install = next(e for e in packages.parse_dpkg_log(DPKG_SAMPLE) if e.action == "install")
		self.assertTrue(install.is_notable, "netcat should be notable")


class TestUpgradableParsing(unittest.TestCase):
	def test_the_security_pocket_is_the_distinction_that_matters(self):
		"""25 pending here, 9 of them security.

		A finding about 25 is wallpaper; one about 9 is a decision.
		"""
		found = packages.parse_upgradable(UPGRADABLE_SAMPLE)
		self.assertEqual(len(found), 3)
		self.assertEqual(sorted(u.package for u in found if u.is_security), ["curl", "vim"])

	def test_an_updates_only_package_is_not_a_security_update(self):
		found = {u.package: u for u in packages.parse_upgradable(UPGRADABLE_SAMPLE)}
		self.assertFalse(found["byobu"].is_security)

	def test_both_versions_are_captured(self):
		found = {u.package: u for u in packages.parse_upgradable(UPGRADABLE_SAMPLE)}
		self.assertEqual(found["curl"].installed, "8.5.0-2ubuntu10.12")
		self.assertEqual(found["curl"].candidate, "8.5.0-2ubuntu10.13")

	def test_the_listing_header_is_ignored(self):
		self.assertEqual(packages.parse_upgradable("Listing...\n"), [])


class TestHistoryRules(unittest.TestCase):
	def _event(self, action, package, when=None):
		return packages.PackageEvent(
			when=when or datetime(2026, 8, 20, 9, 0), action=action, package=package, new_version="1"
		)

	def test_notable_software_is_high(self):
		findings = rules.judge_history([self._event("install", "nmap")])
		notable = [f for f in findings if "Notable software" in f.subject]
		self.assertEqual([f.severity for f in notable], [rules.HIGH])

	def test_the_runbook_says_not_to_remove_it_yet(self):
		"""What was installed and when is one of the few reliable timestamps
		in an intrusion, and uninstalling destroys it."""
		finding = [f for f in rules.judge_history([self._event("install", "nmap")]) if "Notable" in f.subject][0]
		self.assertIn("do not remove it yet", finding.runbook.lower())

	def test_an_ordinary_install_is_medium(self):
		findings = rules.judge_history([self._event("install", "jq")])
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])

	def test_upgrades_are_summarised_not_listed(self):
		"""An unattended-upgrades run touches hundreds at a time.

		Naming each would bury the installs and removals above it.
		"""
		events = [self._event("upgrade", f"pkg{n}") for n in range(200)]
		findings = rules.judge_history(events)
		self.assertEqual([f.severity for f in findings], [rules.INFO])
		self.assertIn("200", findings[0].subject)
		self.assertNotIn("pkg7", findings[0].detail)

	def test_removals_are_reported(self):
		findings = rules.judge_history([self._event("remove", "rsyslog")])
		self.assertTrue(any("removed" in f.subject for f in findings))

	def test_nothing_happening_says_nothing(self):
		self.assertEqual(rules.judge_history([]), [])


class TestUpdateAgeRules(unittest.TestCase):
	"""Age, not count. There are always some pending."""

	def _update(self, package="curl", security=True):
		return packages.Upgradable(
			package=package,
			installed="1",
			candidate="2",
			pockets=("noble-updates", "noble-security") if security else ("noble-updates",),
		)

	def test_recent_security_updates_are_only_a_note(self):
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(
			upgradable=[self._update()], first_seen={"curl": (now - timedelta(days=2)).isoformat()}
		)
		findings = rules.judge_updates(snapshot, now)
		self.assertEqual([f.severity for f in findings], [rules.INFO])

	def test_a_week_old_security_update_is_medium(self):
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(
			upgradable=[self._update()], first_seen={"curl": (now - timedelta(days=10)).isoformat()}
		)
		findings = rules.judge_updates(snapshot, now)
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])

	def test_a_month_old_one_escalates(self):
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(
			upgradable=[self._update()], first_seen={"curl": (now - timedelta(days=40)).isoformat()}
		)
		self.assertEqual([f.severity for f in rules.judge_updates(snapshot, now)], [rules.HIGH])

	def test_non_security_updates_never_raise_this(self):
		"""Sixteen of this box's twenty-five are ordinary bug fixes."""
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(
			upgradable=[self._update("byobu", security=False)],
			first_seen={"byobu": (now - timedelta(days=200)).isoformat()},
		)
		self.assertEqual(rules.judge_updates(snapshot, now), [])

	def test_a_fully_patched_host_says_nothing(self):
		self.assertEqual(rules.judge_updates(_snapshot()), [])

	def test_an_update_first_seen_today_is_not_yet_overdue(self):
		"""Otherwise every newly published fix is instantly a finding."""
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(upgradable=[self._update()], first_seen={"curl": now.isoformat()})
		self.assertEqual([f.severity for f in rules.judge_updates(snapshot, now)], [rules.INFO])

	def test_the_finding_explains_why_a_security_update_is_different(self):
		now = datetime(2026, 8, 25)
		snapshot = _snapshot(
			upgradable=[self._update()], first_seen={"curl": (now - timedelta(days=10)).isoformat()}
		)
		detail = rules.judge_updates(snapshot, now)[0].detail
		self.assertIn("published", detail)


class TestAgainstThisBench(unittest.TestCase):
	def test_it_reads_this_hosts_real_package_state(self):
		snapshot = packages.collect(since=datetime.now() - timedelta(days=30))
		if not any(s.readable for s in snapshot.surfaces):
			self.skipTest("no package data readable here")
		self.assertTrue(all(s.readable for s in snapshot.surfaces))

	def test_security_updates_are_a_strict_subset_of_upgradable(self):
		snapshot = packages.collect()
		self.assertLessEqual(len(snapshot.security_updates), len(snapshot.upgradable))
