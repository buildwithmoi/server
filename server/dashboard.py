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

	# A day before ingestion started is not a quiet day, and drawing it as a
	# zero is a claim this app cannot support. The first read looks back
	# `bootstrap_hours` — 24 by default — so on a 7-day chart five of the days
	# were simply never read, and they rendered exactly like a silent weekend.
	first = collected_from()

	buckets: dict[str, dict] = {}
	for offset in range(days, -1, -1):
		day = add_days(now_datetime(), -offset).date()
		key = str(day)
		buckets[key] = {
			"day": key,
			"success": 0,
			"failure": 0,
			"info": 0,
			"collected": bool(first and day >= first.date()),
		}

	for row in rows:
		key = str(row.day)
		if key in buckets:
			buckets[key][(row.outcome or "info").lower()] = row.n

	return list(buckets.values())


def collected_from():
	"""The oldest event this machine actually holds, or None.

	Used to separate "nothing happened" from "nobody looked", which are the
	same picture on a bar chart and opposite facts about a server.
	"""
	value = frappe.db.sql("SELECT MIN(event_time) FROM `tabSSH Auth Event`")
	return value[0][0] if value and value[0] else None


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
		"collection": collection_surface(),
	}


def collection_surface() -> dict:
	"""Whether this machine can be read at all, and by whom.

	"Monitoring is on and nothing has arrived" has two completely different
	causes and they looked identical: a quiet server, or a reader that cannot
	open a single file. On the first machine this app was installed on it was
	the second — the bench user was not in `adm`, so neither the journal nor
	auth.log was readable — and the install script said so, in a terminal, once,
	while the dashboard went on reporting zeros with no explanation.

	The OS user is included because the fix is a command with that user's name
	in it, and an operator reading this page is not necessarily the one who
	created the account.
	"""
	import getpass

	from frappe.utils.scheduler import is_scheduler_inactive

	from server.install import check_prerequisites
	from server.ssh import sources

	try:
		prerequisites = check_prerequisites()
		logs = prerequisites.get("logs", {})
	except Exception:  # noqa: BLE001
		logs = {}

	detected, explanation = sources.detect_source()

	try:
		user = getpass.getuser()
	except Exception:  # noqa: BLE001
		user = ""

	try:
		# Nothing here runs on its own while the scheduler is paused, and a
		# paused scheduler is invisible from every page in this app.
		paused = bool(is_scheduler_inactive())
	except Exception:  # noqa: BLE001
		paused = False

	return {
		"user": user,
		"journal_readable": bool(logs.get("journal_readable")),
		"auth_log_readable": bool(logs.get("auth_log_readable")),
		"auth_log_path": logs.get("auth_log_path") or "",
		"detected_source": detected,
		"explanation": explanation,
		"scheduler_paused": paused,
		# The replay button is developer-mode only, and offering it on a server
		# that will refuse it is how it came to look like a button that does
		# nothing at all.
		"developer_mode": bool(frappe.conf.get("developer_mode")),
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
		"collected_from": collected_from(),
	}
