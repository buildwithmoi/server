# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""ip-api.com resolver.

Chosen for v1 because it needs no account, no key and no local database, which
means geolocation works the moment the app is installed. Its free tier is
HTTP-only and limited to 45 requests per minute — a constraint the batch
endpoint makes irrelevant, since 100 addresses count as one request.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import ClassVar

from server.geo.base import GeoResolver, GeoResult, ResolverSpec

BATCH_URL = "http://ip-api.com/batch"
MAX_BATCH = 100
TIMEOUT_SECONDS = 20

#: Explicitly requested so the response carries only what we store. Asking for
#: less is both faster and less data about our peers held by a third party.
FIELDS = "status,message,query,countryCode,country,regionName,city,isp,org,as,lat,lon"


class IPAPIResolver(GeoResolver):
	SPEC: ClassVar[ResolverSpec] = ResolverSpec(
		name="ip-api.com",
		label="ip-api.com (free, no key)",
		needs_network=True,
		max_batch=MAX_BATCH,
		description=(
			"Free IP geolocation with no API key. Batches up to 100 addresses per "
			"request, so the 45-requests-per-minute free limit is never approached. "
			"Note the free tier is plain HTTP, so treat the answers as advisory."
		),
	)

	def resolve_many(self, ips: list[str]) -> dict[str, GeoResult]:
		"""Resolve a batch. Never raises — every failure becomes a GeoResult."""
		ips = list(dict.fromkeys(ips))[:MAX_BATCH]
		if not ips:
			return {}

		payload = json.dumps([{"query": ip, "fields": FIELDS} for ip in ips]).encode("utf-8")
		request = urllib.request.Request(
			BATCH_URL,
			data=payload,
			headers={"Content-Type": "application/json", "Accept": "application/json"},
			method="POST",
		)

		try:
			with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
				body = json.loads(response.read().decode("utf-8"))
		except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
			# One provider outage must not abort ingestion. Marking each address
			# with an error lets the rows go to Failed and be retried later.
			message = f"{type(exc).__name__}: {exc}"
			return {ip: GeoResult(ip=ip, error=message) for ip in ips}

		if not isinstance(body, list):
			return {ip: GeoResult(ip=ip, error="unexpected response shape") for ip in ips}

		results: dict[str, GeoResult] = {}
		for index, entry in enumerate(body):
			if not isinstance(entry, dict):
				continue
			# `query` echoes the address back; fall back to positional matching
			# only if the provider omitted it.
			ip = entry.get("query") or (ips[index] if index < len(ips) else None)
			if not ip:
				continue
			results[ip] = self._to_result(ip, entry)

		# Anything the provider silently dropped still needs an answer.
		for ip in ips:
			results.setdefault(ip, GeoResult(ip=ip, error="no response entry"))
		return results

	@staticmethod
	def _to_result(ip: str, entry: dict) -> GeoResult:
		if entry.get("status") != "success":
			return GeoResult(ip=ip, error=str(entry.get("message") or "lookup failed")[:200])
		return GeoResult(
			ip=ip,
			country_code=(entry.get("countryCode") or "").strip().upper() or None,
			country_name=(entry.get("country") or "").strip() or None,
			region=(entry.get("regionName") or "").strip() or None,
			city=(entry.get("city") or "").strip() or None,
			isp=(entry.get("isp") or "").strip() or None,
			org=(entry.get("org") or "").strip() or None,
			asn=(entry.get("as") or "").strip() or None,
			latitude=entry.get("lat"),
			longitude=entry.get("lon"),
		)


SPEC = IPAPIResolver.SPEC
