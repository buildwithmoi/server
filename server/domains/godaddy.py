# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""GoDaddy's DNS API, v3.

TWO THINGS EVERY OLDER TUTORIAL WILL TELL YOU, BOTH NOW WRONG.

  The auth scheme. Every guide and most libraries still show
  `Authorization: sso-key <KEY>:<SECRET>` against `/v1/domains/...`. That is
  deprecated and does not work against v3 at all. v3 wants a **Personal Access
  Token** as an ordinary Bearer credential, created at developer.godaddy.com
  under Keys, with scopes — `domains.domain:read` to list and
  `domains.dns:update` to write.

  The eligibility gate. From early 2024 GoDaddy restricted the DNS API to
  accounts holding ten or more domains, which broke a wave of Let's Encrypt and
  dynamic-DNS tooling and is why most people believe it is unavailable. That
  restriction was **lifted in April 2026**: a single domain is enough. Only the
  availability-search API is still gated.

TTL IS CLAMPED, NOT PASSED THROUGH. GoDaddy rejects anything below 600 seconds
or above 86400 with a 422, and this app's default is 600 — right at the floor.
Clamping here means a caller that asks for 60 gets a working record at 600
rather than a validation error it did not cause and cannot read.

Quotas, for reference: 20,000 requests a month and 60 a second. Nothing this
app does approaches either.
"""

from __future__ import annotations

from server.domains import http
from server.domains.base import DEFAULT_TTL, TYPE_A, DnsProvider, DnsRecord, ProviderSpec, Result, normalise_name

BASE = "https://api.godaddy.com"

#: GoDaddy's own bounds. Outside them the API answers 422.
MIN_TTL = 600
MAX_TTL = 86400


class GoDaddyProvider(DnsProvider):
	SPEC = ProviderSpec(
		name="GoDaddy",
		label="GoDaddy",
		credential_label="Personal Access Token",
		docs_url="https://developer.godaddy.com/keys",
		description=(
			"A v3 Personal Access Token from developer.godaddy.com, with the domains.domain:read "
			"and domains.dns:update scopes. Not the older API key and secret — that scheme is "
			"deprecated and does not work here. A single domain in the account is enough; the "
			"ten-domain restriction was lifted in April 2026."
		),
	)

	# ------------------------------------------------------------------

	def verify(self) -> Result:
		try:
			payload = http.request("GET", f"{BASE}/v3/domains/domain-names", token=self.token)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(zones=tuple(_domains(payload)))

	def list_zones(self) -> Result:
		return self.verify()

	def list_records(self, zone: str) -> Result:
		try:
			payload = http.request(
				"GET", f"{BASE}/v3/domains/zones/{zone}/dns-records", token=self.token
			)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(records=tuple(parse_records(payload)))

	def upsert_record(self, zone: str, record: DnsRecord) -> Result:
		"""Create it, or replace the existing one.

		v3 has no update verb, so an existing record is deleted and re-created.
		The order matters and is the uncomfortable part: between the two calls
		the name does not resolve. It is a sub-second window on a record that is
		either brand new or currently pointing at the wrong host, so the
		alternative — leaving a stale record in place — is worse.
		"""
		existing = self.find_record(zone, record.name, record.type)
		if existing and existing.content == record.content:
			# Already correct. Deleting and re-creating an identical record
			# would open that window for no reason at all.
			return Result(records=(existing,))

		if existing:
			removed = self.delete_record(zone, existing)
			if not removed.ok:
				return removed

		body = [
			{
				"type": record.type,
				"name": normalise_name(record.name, zone),
				"data": record.content,
				"ttl": clamp_ttl(record.ttl),
			}
		]
		try:
			http.request(
				"POST", f"{BASE}/v3/domains/zones/{zone}/dns-records", token=self.token, payload=body
			)
		except http.HttpError as exc:
			return Result.failed(str(exc), exc.body)
		return Result(records=(record,))

	def delete_record(self, zone: str, record: DnsRecord) -> Result:
		if not record.record_id:
			found = self.find_record(zone, record.name, record.type)
			if not found or not found.record_id:
				return Result()
			record = found

		try:
			http.request(
				"DELETE",
				f"{BASE}/v3/domains/zones/{zone}/dns-records/{record.record_id}",
				token=self.token,
			)
		except http.HttpError as exc:
			if exc.status == 404:
				return Result()
			return Result.failed(str(exc), exc.body)
		return Result()


def clamp_ttl(ttl: int | None) -> int:
	"""Into GoDaddy's accepted range.

	Silently, and on purpose. A caller asking for 60 seconds wants "as short as
	allowed"; handing them a 422 they did not cause and cannot act on serves
	nobody.
	"""
	value = int(ttl or DEFAULT_TTL)
	return max(MIN_TTL, min(MAX_TTL, value))


def parse_records(payload) -> list[DnsRecord]:
	"""GoDaddy's record list, reduced to A records.

	The identifier is carried because v3 deletes by id, and an upsert here is a
	delete followed by a create — losing the id would mean the delete could not
	be made.
	"""
	rows = payload.get("dnsRecords", payload) if isinstance(payload, dict) else payload
	if not isinstance(rows, list):
		return []

	found = []
	for row in rows:
		if not isinstance(row, dict):
			continue
		if str(row.get("type", "")).upper() != TYPE_A:
			continue
		found.append(
			DnsRecord(
				name=str(row.get("name", "")),
				type=TYPE_A,
				content=str(row.get("data") or row.get("content") or ""),
				ttl=int(row.get("ttl") or DEFAULT_TTL),
				record_id=str(row.get("recordId") or row.get("id") or ""),
			)
		)
	return found


def _domains(payload) -> list[str]:
	rows = payload.get("domains", payload) if isinstance(payload, dict) else payload
	if not isinstance(rows, list):
		return []

	found = []
	for row in rows:
		if isinstance(row, str):
			found.append(row)
		elif isinstance(row, dict):
			name = row.get("domain") or row.get("domainName") or row.get("name")
			if name:
				found.append(str(name))
	return found
