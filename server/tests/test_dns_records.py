# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading and writing records, rather than only pointing a domain here.

There was one DNS operation in the whole app: "point this name at this host".
Everything else — seeing what a zone holds, changing where a record points,
adding one, removing one — meant leaving for the registrar's console, which is
where half the trouble in a migration starts.
"""

from __future__ import annotations

import inspect
import unittest

from server import api


class WritingIsConfirmedByName(unittest.TestCase):
	"""Same bar as pointing a domain here, for the same reason.

	A wrong record propagates and is cached by resolvers that never asked this
	app's permission. It is not reversible on anybody else's schedule.
	"""

	def test_saving_asks(self):
		source = inspect.getsource(api.save_dns_record)
		self.assertIn('if (confirm or "").strip().lower() != fqdn:', source)

	def test_deleting_asks_too(self):
		source = inspect.getsource(api.delete_dns_record)
		self.assertIn('if (confirm or "").strip().lower() != fqdn:', source)
		self.assertIn("takes it off the internet", source)

	def test_the_bare_zone_is_addressable(self):
		# `@` is how every registrar spells "the domain itself", and a record
		# on the apex is the one somebody reaches for first.
		source = inspect.getsource(api.save_dns_record)
		self.assertIn('or "@"', source)
		self.assertIn('fqdn = zone if label == "@"', source)


class EveryWriteIsRecorded(unittest.TestCase):
	"""A DNS record is how traffic for a name is sent somewhere else."""

	def test_creating_raises_an_event(self):
		self.assertIn("raise_event(", inspect.getsource(api.save_dns_record))

	def test_removing_is_the_more_serious_of_the_two(self):
		# Writing a record redirects a name; removing one takes it off the
		# internet entirely, and nothing else in this app notices.
		self.assertIn('"High"', inspect.getsource(api.delete_dns_record))
		self.assertIn('"Medium"', inspect.getsource(api.save_dns_record))


class ReadingIsNeverCached(unittest.TestCase):
	def test_records_come_from_the_provider(self):
		# A copy of somebody else's DNS is wrong the moment they edit it in the
		# registrar's own console, which is where half of these were made.
		source = inspect.getsource(api.dns_records)
		self.assertIn('"list_records"', source)

	def test_it_reports_this_host_so_a_record_can_be_recognised(self):
		self.assertIn("_public_address()", inspect.getsource(api.dns_records))


if __name__ == "__main__":
	unittest.main()


class TheProviderListHasOneShape(unittest.TestCase):
	"""Three pages read it and two read it wrong.

	`list_domain_providers` returns `{providers, specs}`, not a list. Two
	dialogs indexed the response itself, so their provider dropdown was
	silently empty — including the one added the same day to point a restored
	site at a domain, which would have offered no provider to point it with.
	"""

	def test_the_endpoint_returns_a_mapping_with_providers(self):
		source = inspect.getsource(api.list_domain_providers)
		self.assertIn('"providers": rows', source)

	def test_every_page_reads_it_through_that_key(self):
		import pathlib
		import re

		root = pathlib.Path(__file__).resolve().parents[2] / "serving" / "src"
		wrong = []
		for path in root.rglob("*.vue"):
			text = path.read_text()
			if "domainProvidersResource" not in text:
				continue
			for match in re.finditer(r"providersRes\.data(\??\.\w+)?", text):
				if match.group(1) not in (".providers", "?.providers"):
					wrong.append(f"{path.name}: {match.group(0)}")
		self.assertEqual(wrong, [], f"reads the response as if it were the list: {wrong}")
