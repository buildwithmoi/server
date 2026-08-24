# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Resolver registry and the batch job that drains the pending queue.

Follows the house registry pattern: explicit aliased imports, two module-level
tables, and a dispatcher that never raises. Adding MaxMind GeoLite2 later is a
new module plus two lines here.
"""

from __future__ import annotations

import frappe

from server.geo.base import GeoResolver, GeoResult, ResolverSpec
from server.geo.countries import country_from_code
from server.geo.ip_api import SPEC as _IP_API_SPEC
from server.geo.ip_api import IPAPIResolver as _IPAPIResolver
from server.server.doctype.ip_address_info.ip_address_info import (
	STATUS_FAILED,
	STATUS_PENDING,
	STATUS_PRIVATE,
	STATUS_RESOLVED,
	is_private_address,
)
from server.server.doctype.server_settings.server_settings import get_settings

_RESOLVERS: dict[str, type[GeoResolver]] = {
	_IP_API_SPEC.name: _IPAPIResolver,
}

_SPECS: list[ResolverSpec] = [_IP_API_SPEC]

RESOLVE_JOB_ID = "server::geo_resolve"


def get_resolver_specs() -> list[ResolverSpec]:
	return list(_SPECS)


def get_resolver() -> GeoResolver | None:
	"""Instantiate the configured resolver, or None if geolocation is off."""
	name = get_settings().get_geo_resolver_name()
	resolver_class = _RESOLVERS.get(name)
	return resolver_class() if resolver_class else None


def _apply(name: str, result: GeoResult, resolver_name: str) -> None:
	"""Write one resolver answer onto its IP record."""
	if result.error:
		frappe.db.set_value(
			"IP Address Info",
			name,
			{"status": STATUS_FAILED, "error": result.error[:500], "resolver": resolver_name},
			update_modified=False,
		)
		return

	frappe.db.set_value(
		"IP Address Info",
		name,
		{
			"status": STATUS_RESOLVED,
			"country_code": result.country_code,
			"country": country_from_code(result.country_code),
			"region": result.region,
			"city": result.city,
			"isp": result.isp,
			"org": result.org,
			"asn": result.asn,
			"latitude": result.latitude,
			"longitude": result.longitude,
			"resolved_at": frappe.utils.now_datetime(),
			"resolver": resolver_name,
			"error": None,
		},
		update_modified=False,
	)


def backfill_country(ips: list[str]) -> int:
	"""Copy the resolved country onto the events that referenced the address.

	At insert time an event's IP is usually still Pending, so the denormalised
	country on the event is empty. This fills it in afterwards.

	A JOIN is the honest tool here — it is exactly the case the house style
	reserves `frappe.db.sql` for — and it is scoped to the addresses just
	resolved so it can never turn into a full-table scan.
	"""
	if not ips:
		return 0

	updated = 0
	for doctype in ("SSH Auth Event",):
		# Counted with a SELECT rather than read back from the driver's
		# rowcount: MySQL reports rows CHANGED, not rows MATCHED, so a row
		# already carrying the right value would not be counted and the number
		# would quietly under-report. Scoped to the addresses just resolved, so
		# this is an indexed lookup over at most a batch's worth of IPs.
		pending = frappe.db.sql(
			f"""
			SELECT COUNT(*) FROM `tab{doctype}` e
			JOIN `tabIP Address Info` i ON i.name = e.source_ip
			WHERE e.country IS NULL AND i.country IS NOT NULL AND e.source_ip IN %(ips)s
			""",
			{"ips": tuple(ips)},
		)
		count = pending[0][0] if pending else 0
		if not count:
			continue

		frappe.db.sql(
			f"""
			UPDATE `tab{doctype}` e
			JOIN `tabIP Address Info` i ON i.name = e.source_ip
			SET e.country = i.country
			WHERE e.country IS NULL AND i.country IS NOT NULL AND e.source_ip IN %(ips)s
			""",
			{"ips": tuple(ips)},
		)
		updated += count
	return updated


def resolve_pending(limit: int | None = None) -> dict:
	"""Resolve one batch of Pending addresses. Never raises.

	Returns a summary dict; on any failure the reason is in `error` rather than
	propagating, because this runs on a schedule and a provider outage must not
	turn into a red job every five minutes.
	"""
	try:
		settings = get_settings()
		resolver = get_resolver()
		if resolver is None:
			return {"resolved": 0, "skipped": 0, "reason": "geolocation disabled"}

		batch = min(int(limit or settings.get_geo_batch_size()), resolver.SPEC.max_batch)
		pending = frappe.get_all(
			"IP Address Info",
			filters={"status": STATUS_PENDING},
			pluck="name",
			order_by="creation asc",
			limit_page_length=batch,
		)
		if not pending:
			return {"resolved": 0, "skipped": 0, "reason": "nothing pending"}

		# Belt-and-braces: a private address should never have been marked
		# Pending in the first place, but if one slips through it must not be
		# sent to a third party.
		private = [ip for ip in pending if is_private_address(ip)]
		for ip in private:
			frappe.db.set_value("IP Address Info", ip, "status", STATUS_PRIVATE, update_modified=False)

		lookups = [ip for ip in pending if ip not in set(private)]
		if not lookups:
			frappe.db.commit()
			return {"resolved": 0, "skipped": len(private), "reason": "all pending were private"}

		results = resolver.resolve_many(lookups)
		resolved = 0
		for ip in lookups:
			result = results.get(ip) or GeoResult(ip=ip, error="no result returned")
			_apply(ip, result, resolver.SPEC.name)
			if result.ok:
				resolved += 1

		backfilled = backfill_country([ip for ip in lookups if (results.get(ip) or GeoResult(ip=ip)).ok])
		frappe.db.commit()
		return {
			"resolved": resolved,
			"failed": len(lookups) - resolved,
			"skipped": len(private),
			"events_backfilled": backfilled,
		}
	except frappe.PermissionError as exc:
		return {"error": f"Permission denied: {exc}"}
	except Exception as exc:
		frappe.db.rollback()
		frappe.logger("server").error(f"geo resolve failed: {exc}", exc_info=True)
		return {"error": f"{type(exc).__name__}: {exc}"}


def enqueue_resolve_pending() -> None:
	"""Scheduler entry point."""
	if get_settings().get_geo_resolver_name() == "":
		return

	frappe.enqueue(
		"server.geo.registry.resolve_pending",
		queue="long",
		timeout=600,
		job_id=RESOLVE_JOB_ID,
		deduplicate=True,
	)
