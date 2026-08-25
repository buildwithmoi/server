# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The DNS providers, against captured responses and with no network.

Two APIs with almost nothing in common: Hostinger edits a zone as a SET with a
flag that can replace the whole thing, GoDaddy has per-record create and delete
by id. Most of what is asserted here is that the differences stay inside the
provider modules, and that the one genuinely dangerous call is never made.

The response fixtures are inline rather than in files. They are four lines
each, and a test that shows the shape it is parsing is easier to check against
a provider's docs than one that sends the reader to another file.
"""

import ast
import inspect
import unittest

from server.domains import godaddy, hostinger, registry
from server.domains import base
from server.domains.base import DnsRecord


class TestNameNormalisation(unittest.TestCase):
	"""The apex has four spellings in the wild and a subdomain has two.

	Comparing raw strings means "does this record already exist" answers no
	when it exists, and the wizard then adds a duplicate.
	"""

	def test_every_spelling_of_the_apex_agrees(self):
		for spelling in ("", "@", "example.com", "example.com.", "EXAMPLE.COM"):
			self.assertEqual(base.normalise_name(spelling, "example.com"), "@", spelling)

	def test_a_subdomain_is_reduced_to_its_label(self):
		for spelling in ("app", "app.example.com", "APP.example.com."):
			self.assertEqual(base.normalise_name(spelling, "example.com"), "app", spelling)

	def test_an_unrelated_name_is_left_alone(self):
		self.assertEqual(base.normalise_name("app.other.com", "example.com"), "app.other.com")


class TestSplittingADomain(unittest.TestCase):
	"""Which zone a name belongs to comes from the account, not from dots.

	Counting dots gets `example.co.uk` wrong, and getting it wrong means
	writing a record into a zone that is not the one the operator meant.
	"""

	def test_a_subdomain_is_split_against_the_zone_held(self):
		self.assertEqual(base.split_domain("app.example.com", ["example.com"]), ("example.com", "app"))

	def test_the_apex_splits_to_itself(self):
		self.assertEqual(base.split_domain("example.com", ["example.com"]), ("example.com", "@"))

	def test_a_multi_part_public_suffix_is_not_guessed_at(self):
		self.assertEqual(base.split_domain("app.example.co.uk", ["example.co.uk"]), ("example.co.uk", "app"))

	def test_the_most_specific_zone_wins(self):
		"""An account holding both example.com and staging.example.com.

		A record for a.staging.example.com belongs in the more specific one; a
		first-match loop would put it in whichever came back first.
		"""
		zone, label = base.split_domain("a.staging.example.com", ["example.com", "staging.example.com"])
		self.assertEqual((zone, label), ("staging.example.com", "a"))

	def test_a_domain_in_no_held_zone_returns_nothing(self):
		"""Rather than inventing a zone the credential cannot write to."""
		self.assertEqual(base.split_domain("app.notmine.com", ["example.com"]), ("", ""))


class TestHostingerNeverReplacesAZone(unittest.TestCase):
	"""The single most destructive thing either API can do.

	`overwrite: true` on a zone update replaces every record in it — the MX
	records a business receives mail on, the TXT records proving ownership, the
	apex A record the site is served from — in order to add one subdomain.
	"""

	def test_the_module_never_sets_overwrite_true(self):
		tree = ast.parse(inspect.getsource(hostinger))
		offenders = []
		for node in ast.walk(tree):
			if isinstance(node, ast.Constant) and node.value is True:
				pass  # a bare True is fine; what matters is the key it is under
		for node in ast.walk(tree):
			if not isinstance(node, ast.Dict):
				continue
			for key, value in zip(node.keys, node.values, strict=False):
				if (
					isinstance(key, ast.Constant)
					and key.value == "overwrite"
					and isinstance(value, ast.Constant)
					and value.value is True
				):
					offenders.append(node.lineno)
		self.assertEqual(offenders, [], "a zone update would replace the whole zone")

	def test_the_body_sends_overwrite_false_explicitly(self):
		"""Rather than relying on the provider's default.

		A default that changes on Hostinger's side would turn every subdomain
		addition into a zone replacement, and the whole zone is not something
		to bet on somebody else's default.
		"""
		body = hostinger._zone_body(DnsRecord(name="app", content="1.2.3.4"))
		self.assertIn("overwrite", body)
		self.assertIs(body["overwrite"], False)

	def test_a_delete_names_what_to_remove_rather_than_what_to_keep(self):
		"""Hostinger's delete takes a filter. A filter that matched nothing
		would be harmless; one built the other way round would not be."""
		source = inspect.getsource(hostinger.HostingerProvider.delete_record)
		self.assertIn("filters", source)


class TestHostingerParsing(unittest.TestCase):
	NESTED = [
		{"name": "app", "type": "A", "ttl": 300, "records": [{"content": "1.2.3.4"}]},
		{"name": "@", "type": "MX", "ttl": 300, "records": [{"content": "mail.example.com"}]},
	]
	FLAT = [{"name": "app", "type": "A", "ttl": 300, "content": "1.2.3.4"}]

	def test_the_nested_record_shape_parses(self):
		records = hostinger.parse_zone(self.NESTED, "example.com")
		self.assertEqual([(r.name, r.content) for r in records], [("app", "1.2.3.4")])

	def test_the_flat_record_shape_also_parses(self):
		"""Both are accepted because the published docs pin down neither.

		Guessing one and being wrong yields an empty list, which reads as "the
		subdomain is not there" — so the app would add a duplicate rather than
		report a problem.
		"""
		records = hostinger.parse_zone(self.FLAT, "example.com")
		self.assertEqual([(r.name, r.content) for r in records], [("app", "1.2.3.4")])

	def test_an_envelope_is_unwrapped(self):
		self.assertEqual(len(hostinger.parse_zone({"data": self.NESTED}, "example.com")), 1)

	def test_non_a_records_are_ignored_not_mangled(self):
		"""The MX record in the fixture must not come back as an A record."""
		self.assertTrue(all(r.type == "A" for r in hostinger.parse_zone(self.NESTED, "example.com")))

	def test_a_malformed_response_yields_nothing_rather_than_raising(self):
		for payload in (None, "oops", {"unexpected": 1}, [1, 2, 3]):
			self.assertEqual(hostinger.parse_zone(payload, "example.com"), [])


class TestGoDaddy(unittest.TestCase):
	ROWS = [
		{"type": "A", "name": "app", "data": "1.2.3.4", "ttl": 600, "recordId": "r1"},
		{"type": "MX", "name": "@", "data": "mail.example.com", "ttl": 600, "recordId": "r2"},
	]

	def test_records_parse_and_keep_their_id(self):
		"""v3 deletes by id, and an upsert is a delete then a create.

		Losing the id means the delete cannot be made, so the upsert would
		silently become an append and leave two records for one name.
		"""
		records = godaddy.parse_records(self.ROWS)
		self.assertEqual([(r.name, r.content, r.record_id) for r in records], [("app", "1.2.3.4", "r1")])

	def test_an_envelope_is_unwrapped(self):
		self.assertEqual(len(godaddy.parse_records({"dnsRecords": self.ROWS})), 1)

	def test_ttl_is_clamped_into_the_accepted_range(self):
		"""GoDaddy answers 422 outside 600–86400.

		A caller asking for 60 wants "as short as allowed"; handing back a
		validation error it did not cause and cannot act on serves nobody.
		"""
		self.assertEqual(godaddy.clamp_ttl(60), godaddy.MIN_TTL)
		self.assertEqual(godaddy.clamp_ttl(999999), godaddy.MAX_TTL)
		self.assertEqual(godaddy.clamp_ttl(3600), 3600)
		self.assertEqual(godaddy.clamp_ttl(None), base.DEFAULT_TTL)

	def test_the_deprecated_sso_key_scheme_is_not_used(self):
		"""Every older tutorial shows it; it does not work against v3."""
		source = inspect.getsource(godaddy)
		self.assertNotIn("sso-key", source.split('"""', 2)[-1])

	def test_v3_endpoints_are_used(self):
		self.assertIn("/v3/domains/zones/", inspect.getsource(godaddy.GoDaddyProvider.list_records))


class TestTheRegistryNeverRaises(unittest.TestCase):
	"""A provisioning job that has cloned four gigabytes must not die on a typo."""

	def test_an_unknown_provider_is_a_result_not_an_exception(self):
		result = registry.dispatch("Nonesuch", "token", "verify")
		self.assertFalse(result.ok)
		self.assertIn("Nonesuch", result.error)

	def test_the_error_names_the_providers_that_do_exist(self):
		"""So the operator can see they typed Hostinger with a lowercase h."""
		result = registry.dispatch("hostinger", "token", "verify")
		self.assertIn("Hostinger", result.error)

	def test_a_missing_token_is_reported_before_any_call_is_made(self):
		result = registry.dispatch("Hostinger", "", "verify")
		self.assertFalse(result.ok)
		self.assertIn("No credential", result.error)

	def test_an_unknown_operation_is_a_result(self):
		self.assertFalse(registry.dispatch("Hostinger", "t", "drop_everything").ok)

	def test_a_provider_that_throws_is_caught(self):
		class Exploding:
			def verify(self):
				raise RuntimeError("boom")

		original = registry.PROVIDERS.copy()
		registry.PROVIDERS["Exploding"] = lambda token: Exploding()
		try:
			result = registry.dispatch("Exploding", "t", "verify")
		finally:
			registry.PROVIDERS.clear()
			registry.PROVIDERS.update(original)

		self.assertFalse(result.ok)
		self.assertIn("boom", result.error)

	def test_every_provider_declares_a_spec_with_a_credential_label(self):
		"""An "API token" and a "Personal Access Token" live in different
		places in different dashboards; the wrong word sends people hunting."""
		for spec in registry.get_provider_specs():
			self.assertTrue(spec.credential_label)
			self.assertTrue(spec.docs_url.startswith("https://"))


class TestTheTokenNeverLeaks(unittest.TestCase):
	"""Results are shown in the interface, stored on documents, and — for
	anything raised as a finding — forwarded off the box."""

	def test_a_result_has_no_field_that_could_hold_a_credential(self):
		fields = set(base.Result.__dataclass_fields__)
		self.assertEqual(fields, {"ok", "records", "zones", "error", "detail"})

	def test_the_token_is_sent_as_a_header_not_in_a_url(self):
		"""A token in a query string ends up in access logs and in `detail`."""
		from server.domains import http

		source = inspect.getsource(http.request)
		self.assertIn('sent["Authorization"]', source)
		self.assertNotIn("token=", source.split("def request")[-1].split('"""')[-1])


class TestTheHttpClientIdentifiesItself(unittest.TestCase):
	def test_a_user_agent_is_always_sent(self):
		"""Measured, not stylistic: Hostinger's API is behind Cloudflare, which
		answers urllib's default `Python-urllib/3.14` with 403 — a status that
		reads exactly like a rejected token, on the one call whose job is to
		tell you whether your token works. With a User-Agent set, the same
		request returns 401 for a bad token, which is the truth.
		"""
		from server.domains import http

		self.assertTrue(http.USER_AGENT)
		self.assertIn("User-Agent", inspect.getsource(http.request))

	def test_a_403_is_explained_as_scope_or_bot_filter_not_just_a_number(self):
		from server.domains import http

		self.assertIn("scope", http._explain(403, ""))

	def test_the_provider_body_is_appended_to_the_explanation(self):
		"""The body usually says more than the status — a missing scope is
		named there and nowhere else."""
		from server.domains import http

		message = http._explain(403, '{"message":"missing scope domains.dns:update"}')
		self.assertIn("domains.dns:update", message)


class TestTheCommandsThatActuallyServeTheDomain(unittest.TestCase):
	"""A DNS record is the first step and the smallest one.

	Frappe also has to be told the site answers to the name, DNS multitenancy
	has to be on, and nginx has to be regenerated and reloaded. Leaving those
	out would mean the app reports success on a domain that never answers.
	"""

	def setUp(self):
		from server.bench import commands

		self.commands = commands

	def test_add_domain_is_bench_scoped_with_its_own_site_flag(self):
		"""`bench setup add-domain` takes its OWN --site.

		The global one this app normally uses is rejected outright —
		`bench --site x setup ...` fails with "No such option: --site" — so a
		site-scoped entry here would build an argv that cannot run.
		"""
		entry = self.commands.get("bench.add-domain")
		self.assertEqual(entry.scope, self.commands.SCOPE_BENCH)
		argv = self.commands.build_argv(
			entry, "/usr/local/bin/bench", None, {"site": "a.example.com", "domain": "app.example.com"}
		)
		self.assertEqual(argv[1:], ["setup", "add-domain", "--site", "a.example.com", "app.example.com"])

	def test_a_domain_that_could_be_a_git_option_is_refused(self):
		"""Validated, not merely passed as a list element.

		`shell=False` is not input validation — this app has been caught by
		exactly that before, with a git remote beginning with `--`.
		"""
		entry = self.commands.get("bench.add-domain")
		with self.assertRaises(self.commands.CommandRefused):
			self.commands.build_argv(
				entry, "/b", None, {"site": "x", "domain": "--upload-pack=touch /tmp/x"}
			)

	def test_a_bare_label_is_not_a_domain(self):
		entry = self.commands.get("bench.add-domain")
		with self.assertRaises(self.commands.CommandRefused):
			self.commands.build_argv(entry, "/b", None, {"site": "x", "domain": "localhost"})

	def test_dns_multitenant_accepts_only_on_or_off(self):
		entry = self.commands.get("bench.dns-multitenant")
		self.assertEqual(
			self.commands.build_argv(entry, "/b", None, {"state": "on"})[1:],
			["config", "dns_multitenant", "on"],
		)
		with self.assertRaises(self.commands.CommandRefused):
			self.commands.build_argv(entry, "/b", None, {"state": "maybe"})

	def test_nginx_regeneration_answers_its_own_prompt(self):
		"""`bench setup nginx` asks for confirmation, and a job has no stdin.

		Without --yes it would abort every time, which is the class of failure
		this app's whole subprocess design exists to prevent.
		"""
		argv = self.commands.build_argv(self.commands.get("bench.setup-nginx"), "/b")
		self.assertIn("--yes", argv)

	def test_reload_nginx_is_listed_but_refused(self):
		"""Listed rather than hidden, with the reason attached.

		It needs root, and this app runs as the bench user with no way to
		escalate — which is precisely why it can be given a web interface.
		Hiding it would send somebody hunting for a command that plainly exists.
		"""
		entry = self.commands.get("bench.reload-nginx")
		self.assertFalse(entry.runnable)
		self.assertIn("root", entry.unsupported_reason)
		with self.assertRaises(self.commands.CommandRefused):
			self.commands.build_argv(entry, "/b")
