# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Read-only queries backing the /serving dashboard.

WHY ONE OVERVIEW CALL RATHER THAN SIX. A single-page app that fires six
requests to paint one screen shows six independent spinners and finishes when
the slowest returns. Everything the landing page needs is assembled here in one
round trip, so the page has exactly one loading state and one failure mode.

Query style follows the house rule: `frappe.get_all` wherever it fits, and
`frappe.db.sql` only for the GROUP BY and JOIN work it cannot express — always
parameterised, always `as_dict`.
"""

from __future__ import annotations

import frappe
from frappe.utils import add_days, now_datetime

AUTH = "SSH Auth Event"
SUDO = "SSH Sudo Command"
IPINFO = "IP Address Info"

#: Cap on any list this module will return in one call. The dashboard is a
#: summary; anything that wants more should be paging through a list endpoint.
MAX_ROWS = 200


def _window(days: int) -> tuple[str, int]:
	"""Clamp the requested window and return (cutoff, days)."""
	days = max(1, min(int(days or 7), 365))
	return add_days(now_datetime(), -days), days


def get_totals(days: int = 7) -> dict:
	"""Headline counters for the current window."""
	cutoff, days = _window(days)

	rows = frappe.db.sql(
		"""
		SELECT outcome, COUNT(*) AS n
		FROM `tabSSH Auth Event`
		WHERE event_time >= %(cutoff)s
		GROUP BY outcome
		""",
		{"cutoff": cutoff},
		as_dict=True,
	)
	by_outcome = {row.outcome: row.n for row in rows}

	distinct_ips = frappe.db.sql(
		"""
		SELECT COUNT(DISTINCT source_ip) AS n
		FROM `tabSSH Auth Event`
		WHERE event_time >= %(cutoff)s AND outcome = 'Failure' AND source_ip IS NOT NULL
		""",
		{"cutoff": cutoff},
		as_dict=True,
	)

	return {
		"days": days,
		"success": by_outcome.get("Success", 0),
		"failure": by_outcome.get("Failure", 0),
		"info": by_outcome.get("Info", 0),
		"total": sum(by_outcome.values()),
		"attacking_ips": (distinct_ips[0].n if distinct_ips else 0) or 0,
		"sudo_commands": frappe.db.count(SUDO, {"event_time": (">=", cutoff)}),
		"sudo_denied": frappe.db.count(SUDO, {"event_time": (">=", cutoff), "status": ("!=", "Executed")}),
	}


def get_timeline(days: int = 7) -> list[dict]:
	"""Daily success/failure counts, oldest first, with empty days filled in.

	The gaps matter: a chart that silently omits quiet days compresses the axis
	and makes a burst look like normal traffic.
	"""
	cutoff, days = _window(days)

	rows = frappe.db.sql(
		"""
		SELECT DATE(event_time) AS day, outcome, COUNT(*) AS n
		FROM `tabSSH Auth Event`
		WHERE event_time >= %(cutoff)s
		GROUP BY DATE(event_time), outcome
		""",
		{"cutoff": cutoff},
		as_dict=True,
	)

	buckets: dict[str, dict] = {}
	for offset in range(days, -1, -1):
		key = str(add_days(now_datetime(), -offset).date())
		buckets[key] = {"day": key, "success": 0, "failure": 0, "info": 0}

	for row in rows:
		key = str(row.day)
		if key in buckets:
			buckets[key][(row.outcome or "info").lower()] = row.n

	return list(buckets.values())


def get_by_country(days: int = 7, limit: int = 8) -> list[dict]:
	"""Traffic grouped by resolved country.

	Unresolved addresses are reported as "Unknown" rather than dropped. Hiding
	them would overstate how much of the picture has actually been located.
	"""
	cutoff, _ = _window(days)
	rows = frappe.db.sql(
		"""
		SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS country,
		       COUNT(*) AS total,
		       SUM(outcome = 'Success') AS success,
		       SUM(outcome = 'Failure') AS failure
		FROM `tabSSH Auth Event`
		WHERE event_time >= %(cutoff)s
		GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
		ORDER BY total DESC
		LIMIT %(limit)s
		""",
		{"cutoff": cutoff, "limit": min(int(limit), 50)},
		as_dict=True,
	)
	for row in rows:
		row["success"] = int(row["success"] or 0)
		row["failure"] = int(row["failure"] or 0)
	return rows


def get_top_sources(days: int = 7, limit: int = 10) -> list[dict]:
	"""Busiest failing source addresses, with whatever we know about them."""
	cutoff, _ = _window(days)
	return frappe.db.sql(
		"""
		SELECT e.source_ip                                AS ip,
		       COUNT(*)                                   AS attempts,
		       SUM(e.outcome = 'Success')                 AS successes,
		       COUNT(DISTINCT NULLIF(e.username, ''))     AS usernames,
		       MAX(e.event_time)                          AS last_seen,
		       i.country, i.city, i.isp, i.asn, i.status  AS geo_status
		FROM `tabSSH Auth Event` e
		LEFT JOIN `tabIP Address Info` i ON i.name = e.source_ip
		WHERE e.event_time >= %(cutoff)s
		  AND e.outcome = 'Failure'
		  AND e.source_ip IS NOT NULL
		GROUP BY e.source_ip, i.country, i.city, i.isp, i.asn, i.status
		ORDER BY attempts DESC
		LIMIT %(limit)s
		""",
		{"cutoff": cutoff, "limit": min(int(limit), MAX_ROWS)},
		as_dict=True,
	)


def get_targeted_usernames(days: int = 7, limit: int = 8) -> list[dict]:
	"""Which account names are being guessed."""
	cutoff, _ = _window(days)
	return frappe.db.sql(
		"""
		SELECT username, COUNT(*) AS attempts, SUM(invalid_user) AS invalid
		FROM `tabSSH Auth Event`
		WHERE event_time >= %(cutoff)s AND outcome = 'Failure' AND username IS NOT NULL AND username != ''
		GROUP BY username
		ORDER BY attempts DESC
		LIMIT %(limit)s
		""",
		{"cutoff": cutoff, "limit": min(int(limit), MAX_ROWS)},
		as_dict=True,
	)


def get_recent_events(limit: int = 12) -> list[dict]:
	return frappe.get_all(
		AUTH,
		fields=[
			"name",
			"event_time",
			"event_type",
			"outcome",
			"username",
			"source_ip",
			"country",
			"auth_method",
			"invalid_user",
		],
		order_by="event_time desc",
		limit_page_length=min(int(limit), MAX_ROWS),
	)


def get_recent_sudo(limit: int = 8) -> list[dict]:
	return frappe.get_all(
		SUDO,
		fields=["name", "event_time", "actor", "target_user", "command", "status", "failure_reason"],
		order_by="event_time desc",
		limit_page_length=min(int(limit), MAX_ROWS),
	)


def get_health() -> dict:
	"""Is ingestion actually working? Shown as a banner, not buried in a form.

	A monitoring dashboard that looks calm because nothing is being ingested is
	worse than no dashboard, so this is surfaced on the landing page.
	"""
	from server.server.doctype.server_settings.server_settings import get_settings

	settings = get_settings()
	checkpoints = frappe.get_all(
		"Server Ingest Checkpoint",
		fields=[
			"source",
			"last_run_at",
			"last_run_status",
			"records_inserted",
			"records_skipped",
			"records_unparsed",
			"last_error",
		],
		order_by="modified desc",
	)
	pending_geo = frappe.db.count(IPINFO, {"status": "Pending"})

	return {
		"monitoring_enabled": bool(settings.ssh_monitoring_enabled),
		"log_source": settings.detected_log_source or settings.log_source,
		"geo_enabled": bool(settings.geo_enabled),
		"pending_geolocation": pending_geo,
		"checkpoints": checkpoints,
		"fixture_rows": frappe.db.count(AUTH, {"ingest_source": "fixture"}),
	}


def get_overview(days: int = 7) -> dict:
	"""Everything the landing page needs, in one round trip."""
	days = max(1, min(int(days or 7), 365))
	return {
		"days": days,
		"generated_at": now_datetime(),
		"totals": get_totals(days),
		"timeline": get_timeline(days),
		"by_country": get_by_country(days),
		"top_sources": get_top_sources(days),
		"targeted_usernames": get_targeted_usernames(days),
		"recent_events": get_recent_events(),
		"recent_sudo": get_recent_sudo(),
		"health": get_health(),
	}
