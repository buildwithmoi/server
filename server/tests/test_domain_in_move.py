# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A site that arrives with nothing pointing at it has not arrived.

The move restored a site onto the new machine and stopped there: no DNS record,
no domain on the site, no certificate. Technically complete; unreachable. The
restore dialog had learned to take a domain and the whole-bench move never did,
so the one path that moves eight sites at once was the one that could not point
any of them.
"""

from __future__ import annotations

import unittest

from server.bench import steps
from server.remote import runner


PLAN = {
	"target_bench": "frappe-bench-senchi",
	"source_server_name": "hetzner",
	"source_bench": "frappe-bench-senchi",
	"bench_exists": True,
	"apps": [],
	"sites": [
		{"site_name": "senchi.erpxpand.com", "exists_here": False},
		{"site_name": "hr.erpxpand.com", "exists_here": False},
	],
}


class ADomainPerSite(unittest.TestCase):
	def test_each_site_carries_its_own(self):
		actions = runner.build_actions(
			PLAN,
			domains={"senchi.erpxpand.com": "senchinew.erpxpand.com"},
			domain_provider="hostinger-main",
		)
		moved = {a["remote_site"]: a for a in actions if a["kind"] == runner.KIND_RESTORE}
		self.assertEqual(moved["senchi.erpxpand.com"]["domain"], "senchinew.erpxpand.com")
		self.assertEqual(moved["senchi.erpxpand.com"]["domain_provider"], "hostinger-main")
		# A site nobody named gets nothing, rather than inheriting a neighbour's.
		self.assertEqual(moved["hr.erpxpand.com"]["domain"], "")

	def test_no_domains_changes_nothing(self):
		self.assertEqual(runner.build_actions(PLAN), runner.build_actions(PLAN, domains={}))

	def test_it_reaches_the_restore_call(self):
		import inspect

		source = inspect.getsource(runner.start_next)
		self.assertIn('domain=action.get("domain")', source)
		self.assertIn('domain_provider=action.get("domain_provider")', source)


class ThePreparationSslNeeded(unittest.TestCase):
	"""Three commands the app knew and made somebody type.

	Multitenancy off, the domain not on the site, the nginx config not
	regenerated — all reported as instructions to go and run, per bench, before
	coming back to the dialog. None of the three needs root.
	"""

	def test_they_are_announced_before_the_certificate(self):
		keys = [s.key for s in steps.for_ssl("issue", dry_run=False, prepare=True)]
		self.assertEqual(keys[:4], ["check", "multitenant", "domain", "nginx"])
		self.assertEqual(keys[-1], "issue")

	def test_a_renewal_prepares_nothing(self):
		# Renewal runs certbot against certificates that already exist; there
		# is nothing to set up and a step that does nothing is noise.
		keys = [s.key for s in steps.for_ssl("renew", dry_run=False, prepare=True)]
		self.assertNotIn("multitenant", keys)

	def test_multitenancy_no_longer_refuses_the_run(self):
		# It was blocking, so the panel told the operator to run
		# `bench config dns_multitenant on` themselves. The job does it now.
		from server.bench import ssl

		import inspect

		source = inspect.getsource(ssl.readiness)
		self.assertIn("blocking=False", source)

	def test_the_job_skips_what_is_already_true(self):
		# `bench config` on a value already set still rewrites the file every
		# other bench on the machine reads.
		import inspect

		from server.bench import installer

		source = inspect.getsource(installer._prepare_for_ssl)
		self.assertIn("if not ssl.is_dns_multitenant(", source)
		self.assertIn("already answers to", source)

	def test_it_says_what_it_could_not_do(self):
		import inspect

		from server.bench import installer

		source = inspect.getsource(installer._prepare_for_ssl)
		self.assertIn("reload-nginx", source)


if __name__ == "__main__":
	unittest.main()
