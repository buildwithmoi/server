# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What this host exposes over HTTP, and on what terms.

Two real findings on this bench drove the module and are asserted here: the
site is served over plain HTTP with no TLS at all, and it sends an HSTS header
anyway — which browsers ignore over HTTP, and which suggests a TLS setup that
was planned and never finished.

The guest-endpoint half is graded differently from the transport half, and the
tests say why. Plain HTTP is wrong today and no baseline makes it right.
Fifty-five unauthenticated endpoints in frappe is not a defect — login, ping
and password reset all have to be reachable — so that set is inventoried and
diffed rather than judged.
"""

import os
import tempfile
import unittest

from server.security import web
from server.security import web_rules as rules

PLAIN_HTTP = """
server {
	listen 80;
	listen [::]:80;
	server_name local.16.moi;
	add_header X-Frame-Options "SAMEORIGIN";
	add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
	add_header X-Content-Type-Options nosniff;
	add_header Referrer-Policy "same-origin";
}
"""

TLS_SITE = """
server {
	listen 443 ssl;
	server_name secure.example.com;
	ssl_certificate /etc/letsencrypt/live/secure/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/secure/privkey.pem;
	ssl_protocols TLSv1.2 TLSv1.3;
	add_header X-Frame-Options "SAMEORIGIN";
	add_header Strict-Transport-Security "max-age=63072000";
	add_header X-Content-Type-Options nosniff;
	add_header Referrer-Policy "same-origin";
}
"""

OLD_TLS = """
server {
	listen 443 ssl;
	server_name legacy.example.com;
	ssl_certificate /etc/ssl/legacy.pem;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
}
"""


def _subjects(findings):
	return [f.subject for f in findings]


class TestNginxParsing(unittest.TestCase):
	def test_plain_http_is_recognised(self):
		frontend = web.parse_nginx(PLAIN_HTTP, "/etc/nginx/conf.d/site.conf")
		self.assertEqual(frontend.ports, (80,))
		self.assertFalse(frontend.serves_tls)
		self.assertTrue(frontend.plaintext_only)
		self.assertEqual(frontend.server_names, ("local.16.moi",))

	def test_tls_is_recognised_from_listen_and_from_certificate(self):
		frontend = web.parse_nginx(TLS_SITE)
		self.assertTrue(frontend.serves_tls)
		self.assertFalse(frontend.plaintext_only)
		self.assertTrue(frontend.certificate.endswith("fullchain.pem"))

	def test_headers_are_collected_lowercased(self):
		frontend = web.parse_nginx(PLAIN_HTTP)
		self.assertIn("strict-transport-security", frontend.headers)
		self.assertIn("x-frame-options", frontend.headers)

	def test_protocols_are_captured(self):
		self.assertEqual(web.parse_nginx(OLD_TLS).tls_protocols, ("TLSv1", "TLSv1.1", "TLSv1.2"))

	def test_a_wildcard_server_name_is_not_treated_as_a_name(self):
		frontend = web.parse_nginx("server {\n listen 80;\n server_name _;\n}")
		self.assertEqual(frontend.server_names, ())


class TestTransportRules(unittest.TestCase):
	def test_plain_http_is_high(self):
		findings = rules.judge_transport([web.parse_nginx(PLAIN_HTTP, "x.conf")])
		plain = [f for f in findings if "plain HTTP only" in f.subject]
		self.assertEqual([f.severity for f in plain], [rules.HIGH])

	def test_the_finding_names_what_is_actually_at_risk(self):
		"""Session cookies, not an abstract "unencrypted traffic"."""
		finding = [f for f in rules.judge_transport([web.parse_nginx(PLAIN_HTTP)]) if "plain HTTP" in f.subject][0]
		self.assertIn("session cookie", finding.detail.lower())

	def test_internal_only_is_addressed_rather_than_accepted(self):
		"""It is the first thing anyone says about this finding.

		A runbook that does not answer it gets the alert dismissed.
		"""
		finding = [f for f in rules.judge_transport([web.parse_nginx(PLAIN_HTTP)]) if "plain HTTP" in f.subject][0]
		self.assertIn("internal only", finding.runbook.lower())

	def test_hsts_over_plain_http_is_reported(self):
		"""The real misconfiguration found on this bench."""
		findings = rules.judge_transport([web.parse_nginx(PLAIN_HTTP)])
		self.assertTrue(any("HSTS header over plain HTTP" in f.subject for f in findings))

	def test_hsts_over_tls_is_not_reported(self):
		findings = rules.judge_transport([web.parse_nginx(TLS_SITE)])
		self.assertFalse(any("HSTS" in f.subject for f in findings))

	def test_obsolete_tls_versions_are_named(self):
		findings = rules.judge_transport([web.parse_nginx(OLD_TLS)])
		weak = [f for f in findings if "obsolete TLS" in f.subject]
		self.assertEqual(len(weak), 1)
		self.assertIn("TLSv1.1", weak[0].detail)
		self.assertNotIn("TLSv1.2", weak[0].detail.replace("TLSv1.1", ""))

	def test_a_correctly_configured_tls_site_raises_nothing(self):
		self.assertEqual(rules.judge_transport([web.parse_nginx(TLS_SITE)]), [])

	def test_missing_headers_are_only_judged_on_a_tls_site(self):
		"""A plain-HTTP site already has a bigger finding.

		Adding four header complaints underneath it is noise stacked on the
		thing that actually matters.
		"""
		findings = rules.judge_transport([web.parse_nginx("server {\n listen 80;\n server_name a.b;\n}")])
		self.assertFalse(any("security header" in f.subject for f in findings))


class TestCertificates(unittest.TestCase):
	def test_expiry_is_parsed_from_openssl_output(self):
		sample = "notAfter=Dec 31 23:59:59 2099 GMT\nsubject=CN = example.com\n"
		certificate = web._parse_certificate(sample, "/x.pem")
		self.assertGreater(certificate.days_remaining, 1000)
		self.assertIn("example.com", certificate.subject)

	def test_an_expired_certificate_is_critical(self):
		findings = rules.judge_certificates([web.Certificate(path="/x.pem", days_remaining=-5)])
		self.assertEqual([f.severity for f in findings], [rules.CRITICAL])

	def test_the_runbook_warns_off_bench_renew_lets_encrypt(self):
		"""It calls click.confirm with no non-interactive escape.

		Anyone acting on an expiry alert reaches for it, and it aborts every
		time — which this app learned the hard way and encodes here.
		"""
		finding = rules.judge_certificates([web.Certificate(path="/x.pem", days_remaining=-5)])[0]
		self.assertIn("renew-lets-encrypt", finding.runbook)

	def test_expiring_soon_is_high_and_explains_the_threshold(self):
		findings = rules.judge_certificates([web.Certificate(path="/x.pem", days_remaining=10)])
		self.assertEqual([f.severity for f in findings], [rules.HIGH])
		self.assertIn("renews at 30 days", findings[0].detail)

	def test_a_healthy_certificate_raises_nothing(self):
		self.assertEqual(rules.judge_certificates([web.Certificate(path="/x.pem", days_remaining=75)]), [])

	def test_an_unreadable_certificate_is_reported_not_assumed_fine(self):
		findings = rules.judge_certificates([web.Certificate(path="/x.pem", error="No such file")])
		self.assertEqual([f.severity for f in findings], [rules.MEDIUM])


class TestGuestEndpointDiscovery(unittest.TestCase):
	"""Read from source, not from `frappe.whitelisted`.

	That registry is populated lazily as modules are imported. Asked at
	runtime on this box it returned four; the source holds fifty-seven. A
	check that under-reports the attack surface by an order of magnitude is
	worse than no check at all.
	"""

	SOURCE = '''
import frappe
from frappe.rate_limiter import rate_limit

@frappe.whitelist(allow_guest=True)
def open_one():
	pass

@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(key="x", limit=5)
def guarded():
	pass

@frappe.whitelist()
def needs_login():
	pass

@frappe.whitelist(allow_guest=False)
def explicitly_not_guest():
	pass
'''

	def _scan(self):
		with tempfile.TemporaryDirectory() as tmp:
			app = os.path.join(tmp, "apps", "demo")
			os.makedirs(app)
			with open(os.path.join(app, "api.py"), "w") as handle:
				handle.write(self.SOURCE)
			return web.collect_endpoints(os.path.join(tmp, "apps"), ["demo"])[0]

	def test_only_guest_endpoints_are_returned(self):
		self.assertEqual(sorted(e.function for e in self._scan()), ["guarded", "open_one"])

	def test_allow_guest_false_is_not_a_guest_endpoint(self):
		self.assertNotIn("explicitly_not_guest", [e.function for e in self._scan()])

	def test_rate_limiting_and_method_restriction_are_recorded(self):
		by_name = {e.function: e for e in self._scan()}
		self.assertTrue(by_name["guarded"].rate_limited)
		self.assertTrue(by_name["guarded"].restricted_methods)
		self.assertFalse(by_name["open_one"].rate_limited)

	def test_apps_on_disk_but_not_installed_are_not_counted(self):
		"""This bench has press and erpnext in apps/ and neither installed.

		Counting their hundred and ten guest endpoints would be a hundred and
		ten lies about what is reachable.
		"""
		with tempfile.TemporaryDirectory() as tmp:
			for name in ("installed", "present_only"):
				app = os.path.join(tmp, "apps", name)
				os.makedirs(app)
				with open(os.path.join(app, "api.py"), "w") as handle:
					handle.write(self.SOURCE)
			endpoints, _ = web.collect_endpoints(os.path.join(tmp, "apps"), ["installed"])
		self.assertEqual({e.app for e in endpoints}, {"installed"})

	def test_an_installed_app_missing_from_disk_is_a_coverage_gap(self):
		with tempfile.TemporaryDirectory() as tmp:
			os.makedirs(os.path.join(tmp, "apps"))
			_, surfaces = web.collect_endpoints(os.path.join(tmp, "apps"), ["ghost"])
		self.assertFalse(surfaces[0].readable)


class TestEndpointDrift(unittest.TestCase):
	def _endpoints(self, *names):
		return [web.Endpoint(app="server", module="api", function=n) for n in names]

	def test_the_first_sight_is_an_inventory_not_an_alarm(self):
		findings = rules.judge_endpoints(self._endpoints("a", "b"), previous=None)
		self.assertEqual([f.severity for f in findings], [rules.INFO])

	def test_this_app_names_its_own_guest_endpoints(self):
		"""If the tool reports on unauthenticated endpoints it should start
		by admitting to its own, rather than hiding among the framework's."""
		finding = rules.judge_endpoints(self._endpoints("security_heartbeat"), previous=None)[0]
		self.assertIn("security_heartbeat", finding.detail)

	def test_an_unchanged_set_says_nothing(self):
		endpoints = self._endpoints("a", "b")
		previous = {e.dotted for e in endpoints}
		self.assertEqual(rules.judge_endpoints(endpoints, previous), [])

	def test_a_new_guest_endpoint_is_high(self):
		findings = rules.judge_endpoints(self._endpoints("a", "b"), previous={"api.a"})
		self.assertEqual([f.severity for f in findings], [rules.HIGH])
		self.assertIn("api.b", findings[0].detail)

	def test_a_new_endpoint_without_a_rate_limit_is_called_out(self):
		endpoints = [web.Endpoint(app="server", module="api", function="b", rate_limited=False)]
		finding = rules.judge_endpoints(endpoints, previous=set())[0]
		self.assertIn("no rate limit", finding.detail)

	def test_a_removed_endpoint_is_recorded_as_good_news(self):
		"""The same mechanism that notices a surface growing should show it
		shrinking, or the record is only ever bad news."""
		findings = rules.judge_endpoints(self._endpoints("a"), previous={"api.a", "api.b"})
		self.assertEqual([f.severity for f in findings], [rules.INFO])
		self.assertIn("smaller", findings[0].detail)


class TestAgainstThisBench(unittest.TestCase):
	APPS = "/home/patoo/fb-16-server/apps"

	def setUp(self):
		if not os.path.isdir(self.APPS):
			self.skipTest("not running inside the bench")

	def test_it_finds_this_apps_two_guest_endpoints_and_no_others(self):
		endpoints, _ = web.collect_endpoints(self.APPS, ["server"])
		self.assertEqual(
			sorted(e.function for e in endpoints),
			["get_context_for_dev", "security_heartbeat"],
		)

	def test_the_heartbeat_endpoint_is_rate_limited(self):
		"""Its own tool pointed out that it was not.

		An unauthenticated endpoint that runs database queries and can be
		polled at any rate is a denial-of-service primitive, however small.
		"""
		endpoints, _ = web.collect_endpoints(self.APPS, ["server"])
		heartbeat = next(e for e in endpoints if e.function == "security_heartbeat")
		self.assertTrue(heartbeat.rate_limited)
