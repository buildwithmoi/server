# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""ip-api.com resolver tests.

The transport is stubbed throughout: a test suite that reaches the real internet
is a test suite that fails on a train. What is exercised here is the response
handling, and specifically the failure paths — a geolocation provider is the one
component in this app guaranteed to be unavailable sometimes, and it must never
be able to take ingestion down with it.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from contextlib import contextmanager
from unittest import mock

from server.geo import ip_api
from server.geo.base import GeoResult


@contextmanager
def stub_response(payload, status: int = 200):
	"""Replace urlopen with something that returns `payload` as JSON."""
	body = json.dumps(payload).encode("utf-8")

	class _Response(io.BytesIO):
		def __enter__(self):
			return self

		def __exit__(self, *exc):
			return False

	with mock.patch.object(ip_api.urllib.request, "urlopen", return_value=_Response(body)):
		yield


@contextmanager
def stub_failure(exc: Exception):
	with mock.patch.object(ip_api.urllib.request, "urlopen", side_effect=exc):
		yield


SUCCESS_ENTRY = {
	"status": "success",
	"query": "8.8.8.8",
	"countryCode": "US",
	"country": "United States",
	"regionName": "Virginia",
	"city": "Ashburn",
	"isp": "Google LLC",
	"org": "Google Public DNS",
	"as": "AS15169 Google LLC",
	"lat": 39.03,
	"lon": -77.5,
}


class TestSuccessfulResolution(unittest.TestCase):
	def test_fields_are_mapped(self):
		with stub_response([SUCCESS_ENTRY]):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8"])

		result = results["8.8.8.8"]
		self.assertTrue(result.ok)
		self.assertEqual(result.country_code, "US")
		self.assertEqual(result.country_name, "United States")
		self.assertEqual(result.city, "Ashburn")
		self.assertEqual(result.asn, "AS15169 Google LLC")
		self.assertEqual(result.latitude, 39.03)
		self.assertIsNone(result.error)

	def test_country_code_is_upper_cased(self):
		"""Providers vary; frappe's Country codes are lowercase. Normalise here."""
		with stub_response([dict(SUCCESS_ENTRY, countryCode="us")]):
			result = ip_api.IPAPIResolver().resolve_many(["8.8.8.8"])["8.8.8.8"]
		self.assertEqual(result.country_code, "US")

	def test_results_are_keyed_by_the_echoed_query(self):
		"""Never trust batch ORDER — match on the address the provider echoed."""
		payload = [
			dict(SUCCESS_ENTRY, query="1.1.1.1", countryCode="AU", country="Australia"),
			dict(SUCCESS_ENTRY, query="8.8.8.8"),
		]
		with stub_response(payload):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8", "1.1.1.1"])
		self.assertEqual(results["1.1.1.1"].country_code, "AU")
		self.assertEqual(results["8.8.8.8"].country_code, "US")


class TestFailureHandling(unittest.TestCase):
	"""A provider outage must degrade to 'unknown', never to an exception."""

	def test_network_error_yields_a_result_per_address(self):
		with stub_failure(urllib.error.URLError("no route to host")):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8", "1.1.1.1"])

		self.assertEqual(set(results), {"8.8.8.8", "1.1.1.1"})
		for result in results.values():
			self.assertFalse(result.ok)
			self.assertIn("URLError", result.error)

	def test_timeout_is_handled(self):
		with stub_failure(TimeoutError("timed out")):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8"])
		self.assertFalse(results["8.8.8.8"].ok)

	def test_provider_level_failure_entry(self):
		with stub_response([{"status": "fail", "message": "reserved range", "query": "10.0.0.1"}]):
			result = ip_api.IPAPIResolver().resolve_many(["10.0.0.1"])["10.0.0.1"]
		self.assertFalse(result.ok)
		self.assertEqual(result.error, "reserved range")

	def test_unexpected_response_shape(self):
		with stub_response({"not": "a list"}):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8"])
		self.assertFalse(results["8.8.8.8"].ok)

	def test_missing_entry_still_gets_a_result(self):
		"""Every address asked about must come back, or rows stay Pending forever."""
		with stub_response([SUCCESS_ENTRY]):
			results = ip_api.IPAPIResolver().resolve_many(["8.8.8.8", "1.1.1.1"])
		self.assertEqual(set(results), {"8.8.8.8", "1.1.1.1"})
		self.assertEqual(results["1.1.1.1"].error, "no response entry")


def _make_ctx(request, captured):
	captured["body"] = json.loads(request.data.decode("utf-8"))

	class _Ctx(io.BytesIO):
		def __enter__(self):
			return self

		def __exit__(self, *exc):
			return False

	return _Ctx(b"[]")


class TestBatching(unittest.TestCase):
	def test_batch_is_capped_at_the_provider_maximum(self):
		"""Over-sending is rejected by the provider, so the cap is enforced here."""
		captured = {}
		with mock.patch.object(ip_api.urllib.request, "urlopen") as urlopen:
			urlopen.side_effect = lambda req, timeout=None: _make_ctx(req, captured)
			ip_api.IPAPIResolver().resolve_many([f"9.9.9.{i}" for i in range(150)])

		self.assertEqual(len(captured["body"]), ip_api.MAX_BATCH)

	def test_duplicates_are_collapsed(self):
		captured = {}
		with mock.patch.object(ip_api.urllib.request, "urlopen") as urlopen:
			urlopen.side_effect = lambda req, timeout=None: _make_ctx(req, captured)
			ip_api.IPAPIResolver().resolve_many(["8.8.8.8", "8.8.8.8", "1.1.1.1"])
		self.assertEqual([e["query"] for e in captured["body"]], ["8.8.8.8", "1.1.1.1"])

	def test_empty_input_makes_no_request(self):
		with mock.patch.object(ip_api.urllib.request, "urlopen") as urlopen:
			self.assertEqual(ip_api.IPAPIResolver().resolve_many([]), {})
		urlopen.assert_not_called()


class TestGeoResult(unittest.TestCase):
	def test_ok_requires_a_country_and_no_error(self):
		self.assertTrue(GeoResult(ip="1.2.3.4", country_code="US").ok)
		self.assertFalse(GeoResult(ip="1.2.3.4").ok)
		self.assertFalse(GeoResult(ip="1.2.3.4", country_code="US", error="boom").ok)


if __name__ == "__main__":
	unittest.main()
