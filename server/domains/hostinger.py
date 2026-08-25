# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Hostinger's DNS API.

Base `https://developers.hostinger.com`, Bearer token from hPanel → API.

THE DANGEROUS PART, AND WHY THIS FILE IS SHAPED AROUND IT. Hostinger does not
have per-record endpoints. A zone is manipulated as a SET:

    PUT /api/dns/v1/zones/{domain}     with `overwrite`
    DELETE /api/dns/v1/zones/{domain}  with a filter of {name, type} pairs

`overwrite: true` REPLACES THE ENTIRE ZONE with whatever was sent. On a live
domain that is one call away from deleting every MX record a business receives
mail on, every TXT record proving domain ownership, and the apex A record the
website is served from — to add one subdomain. **This module never sends
`overwrite: true`**, on any path, and there is a test that reads the source to
keep it that way.

`overwrite: false` is documented as "existing records are updated and new ones
added", which is exactly the upsert this app wants and is why the destructive
flag is never needed.

VALIDATE FIRST. Hostinger exposes `POST .../validate`, which checks a proposed
record set without applying it. Given the above, that is used before every
write rather than as an optional nicety: a body this app got subtly wrong
should come back as a validation error, not as an applied change.

STATUS OF THE BODY SHAPE. The endpoints, verbs and auth are confirmed from
Hostinger's own SDK documentation, and the live host was reached from this
machine (it answers 401 to a bad token, with `{"message":"Unauthenticated."}`).
The exact JSON body for a zone update is NOT authoritatively published, so the
shape below follows the SDK's field names and is written defensively: the
parser accepts both of the two plausible shapes rather than guessing one.
**This must be confirmed against a real token before it is trusted**, and
`verify()` is the cheapest way to do that.
"""

from __future__ import annotations

from server.domains import http
from server.domains.base import DEFAULT_TTL, TYPE_A, DnsProvider, DnsRecord, ProviderSpec, Result, normalise_name

BASE = "https://developers.hostinger.com"


class HostingerProvider(DnsProvider):
	SPEC = ProviderSpec(
		name="Hostinger",
		label="Hostinger",
		credential_label="API token",
		docs_url="https://developers.hostinger.com/",
		description=(
			"Created in hPanel under API. Manages DNS for domains in this Hostinger account. "
			"Hostinger edits zones as a whole rather than per record, so this app updates "
			"records additively and never uses the flag that replaces a zone."
		),
	)

	# ------------------------------------------------------------------

	def verify(self) -> Result:
		try:
			payload = http.request("GET", f"{BASE}/api/domains/v1/portfolio", token=self.token)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(zones=tuple(_domains_from_portfolio(payload)))

	def list_zones(self) -> Result:
		return self.verify()

	def list_records(self, zone: str) -> Result:
		try:
			payload = http.request("GET", f"{BASE}/api/dns/v1/zones/{zone}", token=self.token)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(records=tuple(parse_zone(payload, zone)))

	def upsert_record(self, zone: str, record: DnsRecord) -> Result:
		body = _zone_body(record)

		# Checked before it is applied, because the write endpoint is the one
		# that can destroy a zone if this app ever gets the body wrong.
		try:
			http.request("POST", f"{BASE}/api/dns/v1/zones/{zone}/validate", token=self.token, payload=body)
		except http.HttpError as exc:
			# A provider that has no validate endpoint, or has renamed it,
			# should not stop a legitimate update — but anything it actively
			# refuses must stop here.
			if exc.status not in (404, 405):
				return Result.failed(f"Hostinger refused the record: {exc}", exc.body)

		try:
			http.request("PUT", f"{BASE}/api/dns/v1/zones/{zone}", token=self.token, payload=body)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(records=(record,))

	def delete_record(self, zone: str, record: DnsRecord) -> Result:
		body = {"filters": [{"name": normalise_name(record.name, zone), "type": record.type}]}
		try:
			http.request("DELETE", f"{BASE}/api/dns/v1/zones/{zone}", token=self.token, payload=body)
		except http.HttpError as exc:
			if exc.status == 404:
				# Already gone is the outcome that was asked for.
				return Result()
			return Result.failed(str(exc), exc.body)
		return Result()


def _zone_body(record: DnsRecord) -> dict:
	"""The body for a zone update.

	`overwrite` is present and explicitly False. Sending it rather than relying
	on the default is deliberate: a default that changes on Hostinger's side
	would silently turn every subdomain addition into a zone replacement, and
	the whole zone is not something to bet on someone else's default.
	"""
	return {
		"overwrite": False,
		"zone": [
			{
				"name": record.name,
				"type": record.type,
				"ttl": int(record.ttl or DEFAULT_TTL),
				"records": [{"content": record.content}],
			}
		],
	}


def _domains_from_portfolio(payload) -> list[str]:
	"""Domain names out of the portfolio response, whatever it is wrapped in.

	Hostinger's responses are sometimes a bare list and sometimes `{"data": …}`.
	Handling both is three lines here and avoids an integration that works
	until the day they add an envelope.
	"""
	rows = payload.get("data", payload) if isinstance(payload, dict) else payload
	if not isinstance(rows, list):
		return []

	found = []
	for row in rows:
		if isinstance(row, str):
			found.append(row)
		elif isinstance(row, dict):
			name = row.get("domain") or row.get("name")
			if name:
				found.append(str(name))
	return found


def parse_zone(payload, zone: str) -> list[DnsRecord]:
	"""A Hostinger zone response, flattened to A records.

	Accepts BOTH plausible shapes, because the published documentation does not
	pin one down: a record set carrying a nested `records: [{content}]` list,
	and a flat record carrying `content` directly. Guessing one and being wrong
	would mean an empty record list, which reads as "the subdomain is not there"
	and makes the app add a duplicate.
	"""
	rows = payload.get("data", payload) if isinstance(payload, dict) else payload
	if not isinstance(rows, list):
		return []

	found: list[DnsRecord] = []
	for row in rows:
		if not isinstance(row, dict):
			continue
		if str(row.get("type", "")).upper() != TYPE_A:
			continue

		name = str(row.get("name", ""))
		ttl = int(row.get("ttl") or DEFAULT_TTL)
		nested = row.get("records")

		if isinstance(nested, list) and nested:
			for entry in nested:
				content = entry.get("content") if isinstance(entry, dict) else entry
				if content:
					found.append(DnsRecord(name=name, type=TYPE_A, content=str(content), ttl=ttl))
		elif row.get("content"):
			found.append(DnsRecord(name=name, type=TYPE_A, content=str(row["content"]), ttl=ttl))

	return found
