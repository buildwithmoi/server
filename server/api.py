# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Every whitelisted endpoint in this app, behind one shared guard.

House pattern: endpoints live in a single module rather than scattered across
doctype controllers, so the complete remotely-callable surface of the app can be
reviewed by reading one file. Every function starts with an `_assert_*` guard.
"""

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import frappe

from server import dashboard
from server.geo import registry
from server.server.doctype.server_settings.server_settings import get_settings
from server.ssh import ingest, parser, sources


def _assert_server_admin() -> None:
	"""Only System Managers may touch anything in this app.

	This app reads the host's authentication log and can run bench commands as
	the frappe user. There is no meaningful "read-only user" tier here: the log
	itself is sensitive (it names accounts and source addresses), so access is
	all-or-nothing and the bar is System Manager.
	"""
	if frappe.session.user == "Guest":
		frappe.throw("Please log in.", frappe.PermissionError)
	frappe.only_for("System Manager", message=True)


def _assert_developer_mode() -> None:
	"""Guard for endpoints that exist purely to rehearse against fixtures."""
	if not frappe.conf.developer_mode:
		frappe.throw(
			"This endpoint is only available in developer mode. It replays canned "
			"log fixtures, which would put fictional events into a production "
			"audit trail.",
			frappe.PermissionError,
			title="Developer Mode Only",
		)


# ---------------------------------------------------------------------------
# Dashboard (consumed by the /serving SPA)
# ---------------------------------------------------------------------------


@frappe.whitelist()
def get_overview(days: int = 7) -> dict:
	"""Everything the dashboard landing page needs, in one request."""
	_assert_server_admin()
	return dashboard.get_overview(days=days)


@frappe.whitelist()
def get_health() -> dict:
	"""Is ingestion actually working, and what did the last pass do?

	Separate from `check_log_source`, which probes the machine. This reports
	what the reader has actually done — the two answer different questions and
	conflating them meant the Settings page asked one and rendered the other.
	"""
	_assert_server_admin()
	return dashboard.get_health()


@frappe.whitelist()
def list_auth_events(
	start: int = 0,
	page_length: int = 50,
	outcome: str | None = None,
	event_type: str | None = None,
	username: str | None = None,
	source_ip: str | None = None,
	country: str | None = None,
	search: str | None = None,
) -> dict:
	"""Paginated SSH Auth Events, newest first.

	Returns `total` alongside the rows so the SPA can render a real pager rather
	than guessing whether another page exists.
	"""
	_assert_server_admin()

	filters: dict = {}
	if outcome:
		filters["outcome"] = outcome
	if event_type:
		filters["event_type"] = event_type
	if username:
		filters["username"] = username
	if source_ip:
		filters["source_ip"] = source_ip
	if country:
		filters["country"] = country
	if search:
		filters["raw_message"] = ("like", f"%{search}%")

	fields = [
		"name",
		"event_time",
		"event_type",
		"outcome",
		"username",
		"invalid_user",
		"auth_method",
		"source_ip",
		"source_port",
		"country",
		"session_key",
		"hostname",
		"ingest_source",
		"raw_message",
	]
	return {
		"rows": frappe.get_all(
			"SSH Auth Event",
			filters=filters,
			fields=fields,
			order_by="event_time desc",
			limit_start=max(int(start), 0),
			limit_page_length=min(max(int(page_length), 1), 200),
		),
		"total": frappe.db.count("SSH Auth Event", filters),
	}


@frappe.whitelist()
def list_sudo_commands(
	start: int = 0,
	page_length: int = 50,
	actor: str | None = None,
	status: str | None = None,
	search: str | None = None,
) -> dict:
	"""Paginated sudo commands, newest first."""
	_assert_server_admin()

	filters: dict = {}
	if actor:
		filters["actor"] = actor
	if status:
		filters["status"] = status
	if search:
		filters["command"] = ("like", f"%{search}%")

	return {
		"rows": frappe.get_all(
			"SSH Sudo Command",
			filters=filters,
			fields=[
				"name",
				"event_time",
				"actor",
				"target_user",
				"tty",
				"pwd",
				"command",
				"status",
				"failure_reason",
				"hostname",
				"ingest_source",
			],
			order_by="event_time desc",
			limit_start=max(int(start), 0),
			limit_page_length=min(max(int(page_length), 1), 200),
		),
		"total": frappe.db.count("SSH Sudo Command", filters),
	}


@frappe.whitelist()
def list_ip_addresses(start: int = 0, page_length: int = 50, status: str | None = None) -> dict:
	"""Paginated IP geolocation cache, most recently seen first."""
	_assert_server_admin()

	filters: dict = {"status": status} if status else {}
	return {
		"rows": frappe.get_all(
			"IP Address Info",
			filters=filters,
			fields=[
				"name",
				"ip_address",
				"status",
				"country",
				"country_code",
				"city",
				"region",
				"isp",
				"org",
				"asn",
				"first_seen",
				"last_seen",
				"error",
			],
			order_by="last_seen desc",
			limit_start=max(int(start), 0),
			limit_page_length=min(max(int(page_length), 1), 200),
		),
		"total": frappe.db.count("IP Address Info", filters),
	}


@frappe.whitelist()
def get_settings_summary() -> dict:
	"""The handful of settings the SPA surfaces, without exposing secrets."""
	_assert_server_admin()
	settings = get_settings()
	return {
		"ssh_monitoring_enabled": bool(settings.ssh_monitoring_enabled),
		"log_source": settings.log_source,
		"detected_log_source": settings.detected_log_source,
		"auth_log_path": settings.auth_log_path,
		"geo_enabled": bool(settings.geo_enabled),
		"geo_resolver": settings.geo_resolver,
		"alerts_enabled": bool(settings.alerts_enabled),
		"failed_login_threshold": settings.failed_login_threshold,
		"allow_app_install": bool(settings.allow_app_install),
		"bench_root": settings.bench_root,
	}


@frappe.whitelist(methods=["POST"])
def set_monitoring_enabled(enabled: bool = False) -> dict:
	"""Toggle the ingest master switch from the SPA.

	Deliberately the ONLY setting the SPA can write. Everything else lives on
	the Desk form, where each field carries the long description explaining what
	it does — a toggle in a dashboard has no room for that, and these are
	settings you want someone to read before changing.
	"""
	_assert_server_admin()
	settings = get_settings()
	settings.db_set("ssh_monitoring_enabled", 1 if frappe.parse_json(enabled) else 0)
	frappe.db.commit()
	sources.clear_cache()
	return {"ssh_monitoring_enabled": bool(settings.ssh_monitoring_enabled)}


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@frappe.whitelist()
def check_log_source() -> dict:
	"""Report which log source is live and whether it can actually be read.

	The first thing to run on a new server. It distinguishes the three failure
	modes that otherwise look identical from the desk: monitoring switched off,
	no readable source at all, and — the dangerous one — journalctl running fine
	but returning only this user's records because of a missing group.
	"""
	_assert_server_admin()

	from server.ssh import journal

	source, explanation = sources.detect_source()
	settings = get_settings()
	path = (settings.auth_log_path or "").strip()

	# Both timezones are reported because a mismatch between them is silent and
	# badly misleading: events land in the database at the right instant but
	# display hours away from when they happened.
	machine_tz = datetime.now().astimezone().tzname()

	return {
		"source": source,
		"explanation": explanation,
		"monitoring_enabled": bool(settings.ssh_monitoring_enabled),
		"site_timezone": frappe.utils.get_system_timezone(),
		"machine_timezone": machine_tz,
		"journalctl_available": journal.is_available(),
		"journal_system_records_visible": journal.can_read_system_records(),
		"auth_log_path": path,
		"auth_log_readable": bool(path and os.access(path, os.R_OK)),
	}


@frappe.whitelist(methods=["POST"])
def run_ingest_now(source: str | None = None) -> dict:
	"""Run one ingest pass synchronously and return its statistics."""
	_assert_server_admin()
	return ingest.run_ingest(source=source)


@frappe.whitelist(methods=["POST"])
def resolve_geolocation(limit: int | None = None, backfill_all: bool = False) -> dict:
	"""Resolve pending IPs now, instead of waiting for the scheduled run.

	`backfill_all` also re-copies the country onto every event whose address is
	already resolved. The scheduled job only backfills the addresses it looked
	up in that run, so this is the repair path for events that were ingested
	before their address had a country — or after the events were reloaded.
	"""
	_assert_server_admin()
	result = registry.resolve_pending(limit=limit)

	if backfill_all:
		resolved = frappe.get_all(
			"IP Address Info",
			filters={"status": "Resolved", "country": ("is", "set")},
			pluck="name",
		)
		result["events_backfilled"] = registry.backfill_country(resolved)
		frappe.db.commit()

	return result


# ---------------------------------------------------------------------------
# Fixture replay
# ---------------------------------------------------------------------------

#: Only these may be replayed. An unrestricted path here would be an arbitrary
#: file read dressed up as a feature.
REPLAYABLE_FIXTURES = ("auth_rfc3339.log", "auth_classic.log")


@frappe.whitelist(methods=["POST"])
def replay_fixture(name: str = "auth_rfc3339.log", days: int = 7) -> dict:
	"""Ingest a checked-in log fixture as if it had just been logged.

	WHY THIS EXISTS. The development machine is WSL2 with no openssh-server, so
	it cannot produce a single real sshd event. Without this there would be no
	way to see the dashboard, the charts or the session correlation work before
	deploying to the real server — and "it compiles" is not evidence.

	WHY THE TIMESTAMPS ARE REBASED. The fixture carries fixed timestamps, and a
	fixed timestamp is useless to a dashboard: it is either slightly in the
	FUTURE, in which case every time window excludes it and every chart reads
	zero, or it drifts further into the past each day until the charts go empty
	anyway. Each replay is therefore shifted so the newest event lands an hour
	ago. `days` replays the fixture once per day going back, which gives the
	time-series charts a shape to draw — and because the shifted timestamps feed
	the dedup hash, each day's rows are distinct rather than colliding.

	Rows are tagged `ingest_source = "fixture"` so they are trivially
	distinguishable from real events, and `purge_fixture_events()` removes them.
	"""
	_assert_server_admin()
	_assert_developer_mode()

	days = max(1, min(int(days), 60))

	if name not in REPLAYABLE_FIXTURES:
		frappe.throw(
			f"Unknown fixture {name!r}. Available: {', '.join(REPLAYABLE_FIXTURES)}.",
			title="No Such Fixture",
		)

	path = os.path.join(frappe.get_app_path("server"), "tests", "fixtures", name)
	if not os.path.exists(path):
		frappe.throw(f"Fixture file missing: {path}")

	with open(path, encoding="utf-8") as fh:
		raw_lines = [line.rstrip("\n") for line in fh]

	lines = [parsed for parsed in (parser.parse_syslog_line(raw) for raw in raw_lines) if parsed is not None]
	if not lines:
		return {"fixture": name, "lines_in_file": len(raw_lines), "read": 0}

	# Anchor on the newest event so the set keeps its internal spacing: session
	# correlation depends on a login and its logout staying next to each other.
	newest = max(line.timestamp for line in lines)
	if newest.tzinfo is None:
		newest = newest.replace(tzinfo=datetime.now().astimezone().tzinfo)
	now = datetime.now(UTC)

	totals = ingest.IngestStats()
	for day in range(days):
		shift = (now - newest) - timedelta(hours=1) - timedelta(days=day)
		shifted = [replace(line, timestamp=line.timestamp + shift) for line in lines]
		stats = ingest.ingest_syslog_lines(shifted, "fixture")
		totals.read += stats.read
		totals.inserted += stats.inserted
		totals.skipped += stats.skipped
		totals.unparsed += stats.unparsed
		totals.ignored += stats.ignored
	frappe.db.commit()

	return {"fixture": name, "lines_in_file": len(raw_lines), "days": days, **totals.as_dict()}


@frappe.whitelist(methods=["POST"])
def purge_fixture_events() -> dict:
	"""Delete every row that came from a replayed fixture.

	The counterpart to `replay_fixture`: rehearsal data must be removable in one
	step, or people stop rehearsing.
	"""
	_assert_server_admin()
	_assert_developer_mode()

	removed = {}
	for doctype in ("SSH Auth Event", "SSH Sudo Command"):
		count = frappe.db.count(doctype, {"ingest_source": "fixture"})
		frappe.db.delete(doctype, {"ingest_source": "fixture"})
		removed[doctype] = count
	frappe.db.commit()
	return removed
