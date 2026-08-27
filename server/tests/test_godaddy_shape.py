# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""GoDaddy v3 wraps every collection in `items`.

The credential authenticated, GoDaddy returned the domain, and this app parsed
zero of them — so the page said "no domains on that credential", which reads as
a verdict about the token. Three rounds were spent on the token, the rename and
the request method before anybody looked at the response body.

The fixtures below are the real thing, captured from the live API on
2026-08-27 with a working Personal Access Token. Addresses are left as they came
back: they are public DNS, which is the entire point of them.
"""

from __future__ import annotations

import unittest

from server.domains import godaddy

#: GET /v3/domains/domain-names
DOMAIN_NAMES = {
	"items": [
		{
			"autoRenew": True,
			"createdAt": "2023-10-21T07:15:22.000Z",
			"domain": "erpxpand.com",
			"expiresAt": "2026-10-21T07:15:22.000Z",
			"links": [{"href": "…", "method": "GET", "rel": "self"}],
			"nameServers": ["ns15.domaincontrol.com", "ns16.domaincontrol.com"],
			"status": "ACTIVE",
		}
	],
	"links": [{"href": "…", "method": "GET", "rel": "self"}],
}

#: GET /v3/domains/zones/{zone}/dns-records
DNS_RECORDS = {
	"items": [
		{"type": "A", "name": "@", "data": "46.62.173.8", "ttl": 600},
		{"type": "A", "name": "121", "data": "135.181.103.186", "ttl": 600},
		{"type": "NS", "name": "@", "data": "ns15.domaincontrol.com", "ttl": 3600},
		{"type": "CNAME", "name": "www", "data": "@", "ttl": 3600},
	],
	"links": [],
}


class TheDomainList(unittest.TestCase):
	def test_items_is_where_v3_puts_them(self):
		self.assertEqual(godaddy._domains(DOMAIN_NAMES), ["erpxpand.com"])

	def test_the_older_shapes_still_parse(self):
		# v1 answered with a bare list, and `domains` was a reasonable guess in
		# between. Both are cheap to keep and neither can be told apart from
		# the outside.
		self.assertEqual(godaddy._domains([{"domain": "a.com"}]), ["a.com"])
		self.assertEqual(godaddy._domains({"domains": [{"domain": "b.com"}]}), ["b.com"])

	def test_a_dict_with_no_list_in_it_is_empty_not_a_crash(self):
		self.assertEqual(godaddy._domains({"links": []}), [])
		self.assertEqual(godaddy._domains({"message": "nope"}), [])


class TheRecordList(unittest.TestCase):
	def test_it_reads_items_too(self):
		found = godaddy.parse_records(DNS_RECORDS)
		self.assertEqual([r.name for r in found], ["@", "121"])

	def test_only_a_records_come_back(self):
		# This app writes A records and nothing else, and showing a CNAME it
		# cannot edit would offer an Edit button that quietly destroys it.
		found = godaddy.parse_records(DNS_RECORDS)
		self.assertTrue(all(r.type == "A" for r in found))

	def test_the_address_is_read_from_data(self):
		found = godaddy.parse_records(DNS_RECORDS)
		self.assertEqual(found[0].content, "46.62.173.8")


class TheFormOffersOnlyWhatItCanDo(unittest.TestCase):
	def test_the_type_list_is_a_only(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "views" / "DnsRecords.vue"
		).read_text()
		self.assertIn('const TYPES = ["A"];', view)


if __name__ == "__main__":
	unittest.main()
