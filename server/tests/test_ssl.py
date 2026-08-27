# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Let's Encrypt argv and readiness tests.

Frappe-free and network-free. Nothing here talks to certbot or Let's Encrypt —
what is being tested is the argv that would be handed to them, which is exactly
the part that has to be right before anything stops nginx.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from server.bench import ssl

BENCH_EXE = "/usr/local/bin/bench"


def make_site(root: str, site: str, config: dict | None = None) -> None:
	path = os.path.join(root, "sites", site)
	os.makedirs(path, exist_ok=True)
	with open(os.path.join(path, "site_config.json"), "w") as handle:
		json.dump(config or {}, handle)


class TestIssueArgv(unittest.TestCase):
	"""Certbot directly, not `bench setup lets-encrypt`.

	bench's path is written to run AS ROOT: it writes
	/etc/letsencrypt/configs/<domain>.cfg with no sudo, and runs certbot with
	no sudo either. As the bench user it fails on the first mkdir, and making
	it work would mean granting `sudo bench setup lets-encrypt *` — a wildcard
	on a command that takes a site name from a browser, which is a root shell
	with extra steps.
	"""

	def setUp(self):
		self._certbot = mock.patch.object(ssl, "certbot_path", lambda: "/usr/bin/certbot")
		self._certbot.start()
		self.addCleanup(self._certbot.stop)

	def test_it_runs_certbot_under_sudo(self):
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com")
		self.assertEqual(argv[:5], ["sudo", "-n", "/usr/bin/certbot", "certonly", "--non-interactive"])
		self.assertNotIn("lets-encrypt", argv)

	def test_nginx_is_started_again_by_a_hook_not_by_a_later_command(self):
		# certbot runs the post-hook even when issuing fails. Sequential is
		# what bench does, and it is why a failed issue there takes every site
		# on the machine offline until somebody notices.
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com")
		self.assertIn("--pre-hook", argv)
		self.assertIn("systemctl stop nginx", argv)
		self.assertIn("--post-hook", argv)
		self.assertIn("systemctl start nginx", argv)

	def test_the_custom_domain_is_what_gets_certified(self):
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com", "shop.example.com")
		self.assertEqual(argv[argv.index("-d") + 1], "shop.example.com")

	def test_an_email_is_used_when_there_is_one(self):
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com", email="ops@example.com")
		self.assertEqual(argv[argv.index("--email") + 1], "ops@example.com")
		self.assertNotIn("--register-unsafely-without-email", argv)

	def test_without_one_it_registers_without_rather_than_inventing_one(self):
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com")
		self.assertIn("--register-unsafely-without-email", argv)

	def test_a_dry_run_is_a_dry_run(self):
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com", dry_run=True)
		self.assertIn("--dry-run", argv)

	def test_issue_needs_a_site(self):
		with self.assertRaises(ssl.SSLRefused):
			ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, None)

	def test_rejects_a_domain_that_is_not_one(self):
		for bad in ("localhost", "not a domain", "example.com; rm -rf /", "-evil.com", "   "):
			with self.subTest(domain=bad), self.assertRaises(ssl.SSLRefused):
				ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "site", bad)

	def test_no_custom_domain_means_the_site_own_domain(self):
		"""Empty is a choice, not a bad value — it means "certify the site"."""
		argv = ssl.build_argv(ssl.MODE_ISSUE, BENCH_EXE, "erp.example.com", "")
		self.assertEqual(argv[argv.index("-d") + 1], "erp.example.com")

	def test_unknown_mode_is_refused(self):
		with self.assertRaises(ssl.SSLRefused):
			ssl.build_argv("delete-everything", BENCH_EXE, "site")


class TestRenewArgv(unittest.TestCase):
	def setUp(self):
		if not ssl.certbot_path():
			self.skipTest("certbot is not installed on this machine")

	def test_renew_does_not_use_the_bench_command(self):
		"""bench's own renew asks for confirmation and cannot be automated.

		`bench renew-lets-encrypt` calls click.confirm with no non-interactive
		escape, so it must never appear in an argv built here.
		"""
		argv = ssl.build_argv(ssl.MODE_RENEW, BENCH_EXE)
		self.assertNotIn("renew-lets-encrypt", argv)
		self.assertIn("renew", argv)
		self.assertEqual(argv[:2], ["sudo", "-n"])

	def test_nginx_is_restarted_by_a_post_hook(self):
		"""The post-hook runs even when renewal fails.

		Stopping nginx and starting it again in sequence — which is what bench
		does — leaves every site offline if the middle step raises.
		"""
		argv = ssl.build_argv(ssl.MODE_RENEW, BENCH_EXE)
		self.assertIn("--post-hook", argv)
		self.assertEqual(argv[argv.index("--post-hook") + 1], "systemctl start nginx")

	def test_dry_run_is_opt_in(self):
		self.assertNotIn("--dry-run", ssl.build_argv(ssl.MODE_RENEW, BENCH_EXE))
		self.assertIn("--dry-run", ssl.build_argv(ssl.MODE_RENEW, BENCH_EXE, dry_run=True))


class TestQuietFailure(unittest.TestCase):
	"""bench reports several SSL failures by printing and exiting 0."""

	def test_missing_multitenancy_is_caught(self):
		message = ssl.quiet_failure(f"some output\n{ssl.NO_MULTITENANCY}\nmore output")
		self.assertIsNotNone(message)
		self.assertIn("dns_multitenant", message)

	def test_other_quiet_failures_are_reported_verbatim(self):
		message = ssl.quiet_failure("No site named erp.example.com")
		self.assertIn("No site named erp.example.com", message)

	def test_a_successful_run_is_not_flagged(self):
		self.assertIsNone(ssl.quiet_failure("Congratulations! Your certificate has been saved."))


class TestSiteDomains(unittest.TestCase):
	def test_host_name_wins_over_the_site_name(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "site1.local", {"host_name": "https://erp.example.com/"})
			domain, extras = ssl.site_domains(root, "site1.local")
			# The scheme and trailing slash have to come off — certbot wants a
			# hostname, not a URL.
			self.assertEqual(domain, "erp.example.com")
			self.assertEqual(extras, [])

	def test_falls_back_to_the_site_name(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "erp.example.com", {})
			domain, _ = ssl.site_domains(root, "erp.example.com")
			self.assertEqual(domain, "erp.example.com")

	def test_extra_domains_are_collected(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "s", {"domains": ["a.example.com", {"domain": "b.example.com"}]})
			_, extras = ssl.site_domains(root, "s")
			self.assertEqual(extras, ["a.example.com", "b.example.com"])

	def test_missing_config_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(ssl.site_domains(root, "nope")[0], "nope")


class TestMultitenancy(unittest.TestCase):
	def test_reads_common_site_config(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites"))
			path = os.path.join(root, "sites", "common_site_config.json")
			with open(path, "w") as handle:
				json.dump({"dns_multitenant": True}, handle)
			self.assertTrue(ssl.is_dns_multitenant(root))

	def test_absent_means_false(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertFalse(ssl.is_dns_multitenant(root))


class TestReadiness(unittest.TestCase):
	def test_reports_every_check_and_a_row_per_site(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "erp.example.com", {})
			report = ssl.readiness(root, [{"name": "erp.example.com", "is_default": True}])

			self.assertEqual({c["key"] for c in report["checks"]}, {"certbot", "sudo", "multitenant"})
			self.assertEqual(len(report["sites"]), 1)
			self.assertTrue(report["sites"][0]["is_default"])
			# ready must never be true while a blocking check is failing.
			blocking_ok = all(c["ok"] for c in report["checks"] if c["blocking"])
			self.assertEqual(report["ready"], blocking_ok)

	def test_a_site_that_cannot_be_certified_says_so(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "localhost", {})
			report = ssl.readiness(root, [{"name": "localhost", "is_default": True}])
			self.assertIn("not a public domain", report["sites"][0]["note"])


if __name__ == "__main__":
	unittest.main()


class TestDNS(unittest.TestCase):
	"""Checked before certbot is asked.

	Let's Encrypt rate-limits failed authorisations per account and the block
	outlasts the mistake, so a domain that cannot possibly validate should never
	cost an attempt.
	"""

	def test_a_domain_that_does_not_resolve_is_a_hard_no(self):
		result = ssl.dns_check("definitely-not-a-real-domain-xyz123456.invalid")
		self.assertEqual(result["level"], "danger")
		self.assertFalse(result["points_here"])

	def test_something_that_is_not_a_domain_is_a_hard_no(self):
		for bad in ("localhost", "not a domain", ""):
			with self.subTest(domain=bad):
				self.assertEqual(ssl.dns_check(bad)["level"], "danger")

	def test_resolving_elsewhere_is_only_a_warning(self):
		"""Behind a proxy or Cloudflare this is entirely normal."""
		result = ssl.dns_check("example.com")
		if not result["resolved"]:
			self.skipTest("no DNS available in this environment")
		self.assertEqual(result["level"], "warn")
		self.assertFalse(result["points_here"])
		self.assertIn("proxy", result["detail"])

	def test_local_ips_are_discoverable(self):
		found = ssl.local_ips()
		self.assertTrue(all(ip.count(".") == 3 for ip in found))

	def test_readiness_carries_a_dns_verdict_per_site(self):
		with tempfile.TemporaryDirectory() as root:
			make_site(root, "erp.example.com", {})
			report = ssl.readiness(root, [{"name": "erp.example.com", "is_default": True}])
			self.assertIn("level", report["sites"][0]["dns"])
