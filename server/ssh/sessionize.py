# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Read auth events, write sessions, link the sudo commands to them.

The thinking lives in `sessions.py`, which has no frappe import and can be
tested against hand-built events. This module is the part that talks to the
database: it decides how far back to look, loads the rows, and writes what
comes back.

HOW FAR BACK. Rebuilding every session on every run would be quadratic in the
size of the log, which is the shape of bug that only shows up once a server
has been running for a year. It looks at a window instead, and the window is
wide enough to contain any session that could still be changing: sessions are
rebuilt from a lookback, and a session already Closed is never revisited.
"""

from __future__ import annotations

import frappe

from server.ssh import sessions as core

DOCTYPE = "SSH Session"

#: How far back to load auth events. Wider than STALE_AFTER so a session that
#: is about to be marked Unknown is still in the window that marks it.
LOOKBACK_HOURS = 60

#: A hard ceiling on one run, so a first run over a year of history cannot
#: take a worker out of circulation. What is left is picked up next tick.
MAX_EVENTS = 20000
MAX_COMMANDS = 20000


def _events(since) -> list[core.Event]:
	rows = frappe.get_all(
		"SSH Auth Event",
		filters={"event_time": [">=", since], "session_key": ["is", "set"]},
		fields=[
			"event_time",
			"event_type",
			"session_key",
			"username",
			"source_ip",
			"country",
			"auth_method",
			"key_fingerprint",
			"audit_session",
			"pid",
			"hostname",
		],
		order_by="event_time asc",
		limit_page_length=MAX_EVENTS,
	)
	return [
		core.Event(
			event_time=row.event_time,
			event_type=row.event_type or "",
			session_key=row.session_key or "",
			username=row.username or "",
			source_ip=row.source_ip or "",
			country=row.country or "",
			auth_method=row.auth_method or "",
			key_fingerprint=row.key_fingerprint or "",
			audit_session=row.audit_session or "",
			pid=row.pid,
			hostname=row.hostname or "",
		)
		for row in rows
	]


def _commands(since) -> list[core.Command]:
	rows = frappe.get_all(
		"SSH Sudo Command",
		filters={"event_time": [">=", since]},
		fields=["name", "event_time", "actor", "audit_session", "hostname"],
		order_by="event_time asc",
		limit_page_length=MAX_COMMANDS,
	)
	return [
		core.Command(
			name=row.name,
			event_time=row.event_time,
			actor=row.actor or "",
			audit_session=row.audit_session or "",
			hostname=row.hostname or "",
		)
		for row in rows
	]


def _write_session(session: core.Session, counts: dict, methods: dict) -> None:
	values = session.as_dict()
	values.pop("event_count", None)
	values["event_count"] = session.event_count
	values["sudo_command_count"] = counts.get(session.session_key, 0)
	values["attribution_method"] = methods.get(session.session_key, "")

	# A Link to a Country or an IP Address Info row that does not exist would
	# fail the whole batch. Ingest creates the IP row inline, but a session
	# built from an event whose geolocation has not run yet has a country
	# string and no Country document to point at.
	if values.get("country") and not frappe.db.exists("Country", values["country"]):
		values["country"] = ""
	if values.get("source_ip") and not frappe.db.exists("IP Address Info", values["source_ip"]):
		values["source_ip"] = ""

	existing = frappe.db.exists(DOCTYPE, session.session_key)
	if existing:
		frappe.db.set_value(DOCTYPE, session.session_key, values, update_modified=False)
		return

	frappe.get_doc({"doctype": DOCTYPE, **values}).insert(ignore_permissions=True)


def run(lookback_hours: int = LOOKBACK_HOURS) -> dict:
	"""Build sessions from recent events and attribute the sudo commands.

	Idempotent: a second run over the same window rewrites the same rows with
	the same values. That is what makes it safe on a schedule and safe to run
	by hand while looking at something.
	"""
	now = frappe.utils.now_datetime()
	since = frappe.utils.add_to_date(now, hours=-lookback_hours)

	events = _events(since)
	if not events:
		return {"sessions": 0, "commands": 0, "note": "no auth events in the window"}

	built = core.build_sessions(events)
	stale = core.close_stale(built, now)

	commands = _commands(since)
	attributions = core.attribute_commands(built, commands)

	counts: dict[str, int] = {}
	methods: dict[str, str] = {}
	for attribution in attributions:
		if not attribution.session_key:
			continue
		counts[attribution.session_key] = counts.get(attribution.session_key, 0) + 1
		# A session whose commands were matched by different means reports the
		# weaker one. Claiming "exact" for a set that is partly inferred is the
		# specific kind of overstatement this whole module is arranged against.
		current = methods.get(attribution.session_key)
		if current != core.BY_USER_AND_TIME:
			methods[attribution.session_key] = attribution.method

	for session in built:
		_write_session(session, counts, methods)

	for attribution in attributions:
		frappe.db.set_value(
			"SSH Sudo Command",
			attribution.command,
			{"ssh_session": attribution.session_key or None, "attribution_method": attribution.method},
			update_modified=False,
		)

	frappe.db.commit()
	summary = core.summarise(built, attributions)
	summary["commands"] = len(commands)
	summary["marked_unknown"] = stale
	return summary


def enqueue_sessionize() -> None:
	"""Scheduler entry point.

	Deduplicated, because a slow run must never stack workers — the same rule
	the ingest job follows, and for the same reason.
	"""
	frappe.enqueue(
		"server.ssh.sessionize.run",
		queue="long",
		job_id="server::ssh_sessionize",
		deduplicate=True,
		enqueue_after_commit=True,
	)
