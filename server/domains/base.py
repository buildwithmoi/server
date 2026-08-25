# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What a DNS provider must be able to do, and what it must never do.

Two providers today (Hostinger and GoDaddy) and the shapes of their APIs have
almost nothing in common — one manipulates a zone as a SET of records with a
flag that can replace the whole thing, the other has per-record create and
delete by id. This interface exists so the wizard above them does not care.

WHY EVERY METHOD RETURNS A RESULT AND NEVER RAISES. The same reasoning as
`GeoResolver.resolve_many`: these calls cross the network to somebody else's
server, and a provider having an outage must not abort a provisioning job that
has already cloned four gigabytes. A failure is a value — `Result(ok=False,
error=…)` — that the caller reports and moves past.

WHY `upsert` RATHER THAN `create`. Pointing a subdomain at this host is
idempotent by nature: run it twice and the desired state is the same. A create
that fails because the record already exists would make the wizard's retry path
the interesting one, and retrying is the case that matters most — a
half-finished provision is re-run far more often than a clean one.

Frappe-free, so a captured API response can be parsed and judged in a test with
no site, no database and no network.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

#: What a subdomain record is, in every provider's model. Deliberately not
#: every record type — this app writes A records pointing at this host and
#: nothing else, and a general-purpose DNS editor is a different product.
TYPE_A = "A"

#: Both providers accept a TTL and both have opinions about the range. Ten
#: minutes is short enough that a wrong record can be corrected quickly and
#: long enough that nobody's resolver is punished for it.
DEFAULT_TTL = 600


@dataclass(frozen=True)
class ProviderSpec:
	"""What a provider is, for the picker and the credentials form."""

	name: str
	label: str
	#: What the operator must paste in, named as that provider names it — an
	#: "API token" and a "Personal Access Token" are found in different places
	#: in different dashboards, and the wrong word sends people hunting.
	credential_label: str
	docs_url: str
	description: str


@dataclass(frozen=True)
class DnsRecord:
	"""One record, normalised across providers.

	`name` is the label relative to the zone (`app`), never the fully qualified
	name (`app.example.com`). Providers disagree about which they want, and
	picking one here means the disagreement is handled in exactly two places
	instead of everywhere a record is built.
	"""

	name: str
	type: str = TYPE_A
	content: str = ""
	ttl: int = DEFAULT_TTL
	#: Provider-assigned identifier, where the provider has one. Hostinger
	#: manipulates zones as sets and has none; GoDaddy needs it to delete.
	record_id: str = ""

	def as_dict(self) -> dict:
		return {
			"name": self.name,
			"type": self.type,
			"content": self.content,
			"ttl": self.ttl,
			"record_id": self.record_id,
		}


@dataclass(frozen=True)
class Result:
	"""The outcome of one provider call. `error` set means it failed."""

	ok: bool = True
	records: tuple[DnsRecord, ...] = ()
	zones: tuple[str, ...] = ()
	error: str = ""
	#: Whatever the provider said, for the operator to read when our summary is
	#: not enough. Never contains the token — see `http.py`.
	detail: str = ""

	@classmethod
	def failed(cls, error: str, detail: str = "") -> "Result":
		return cls(ok=False, error=error, detail=detail)

	def as_dict(self) -> dict:
		return {
			"ok": self.ok,
			"records": [r.as_dict() for r in self.records],
			"zones": list(self.zones),
			"error": self.error,
			"detail": self.detail,
		}


class DnsProvider(ABC):
	"""One registrar's DNS API, reduced to the four things this app needs."""

	SPEC: ClassVar[ProviderSpec]

	def __init__(self, token: str):
		self.token = token

	@abstractmethod
	def verify(self) -> Result:
		"""Does this credential work? Never raises.

		Called from the credentials page, so its `error` is read by a person
		deciding whether they pasted the right string. "401 Unauthorized" is a
		usable answer; a traceback is not.
		"""

	@abstractmethod
	def list_zones(self) -> Result:
		"""The domains this credential can manage. Never raises."""

	@abstractmethod
	def list_records(self, zone: str) -> Result:
		"""Every A record in the zone. Never raises."""

	@abstractmethod
	def upsert_record(self, zone: str, record: DnsRecord) -> Result:
		"""Create the record, or update it if it is already there. Never raises."""

	@abstractmethod
	def delete_record(self, zone: str, record: DnsRecord) -> Result:
		"""Remove the record. Never raises.

		Present so a provisioning run that fails after writing DNS can undo it,
		and so the operator can correct a typo from the app rather than the
		registrar's dashboard.
		"""

	# ------------------------------------------------------------------

	def find_record(self, zone: str, name: str, type_: str = TYPE_A) -> DnsRecord | None:
		"""The existing record for this label, or None.

		Shared rather than abstract: every provider can list, and doing the
		match here means "does it already exist" is answered the same way
		everywhere — including the case both providers get wrong in their own
		way, where the apex is written as `@`, as an empty string, or as the
		domain itself.
		"""
		listing = self.list_records(zone)
		if not listing.ok:
			return None
		wanted = normalise_name(name, zone)
		for record in listing.records:
			if record.type == type_ and normalise_name(record.name, zone) == wanted:
				return record
		return None


def normalise_name(name: str, zone: str) -> str:
	"""The label relative to the zone, in one spelling.

	The apex has four spellings in the wild — ``""``, ``"@"``, the zone itself,
	and the zone with a trailing dot — and a subdomain has two, bare or fully
	qualified. Comparing raw strings means "does this record exist" answers no
	when it exists, and the wizard then creates a duplicate.
	"""
	text = (name or "").strip().rstrip(".").lower()
	zone_text = (zone or "").strip().rstrip(".").lower()

	if text in ("", "@", zone_text):
		return "@"
	if zone_text and text.endswith(f".{zone_text}"):
		return text[: -(len(zone_text) + 1)]
	return text


def split_domain(fqdn: str, zones: list[str]) -> tuple[str, str]:
	"""Split `app.example.com` into ("example.com", "app") given the zones held.

	Guessing by counting dots does not work — `example.co.uk` is a zone and
	`co.uk` is not — so the answer comes from the zone list the provider
	actually returned. The longest matching zone wins, because a credential
	holding both `example.com` and `staging.example.com` should put a record
	for `a.staging.example.com` in the more specific one.
	"""
	target = (fqdn or "").strip().rstrip(".").lower()
	best = ""
	for zone in zones:
		candidate = (zone or "").strip().rstrip(".").lower()
		if not candidate:
			continue
		if target == candidate or target.endswith(f".{candidate}"):
			if len(candidate) > len(best):
				best = candidate

	if not best:
		return "", ""
	return best, normalise_name(target, best)
