# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Every whitelisted endpoint in this app, behind one shared guard.

House pattern: endpoints live in a single module rather than scattered across
doctype controllers, so the complete remotely-callable surface of the app can be
reviewed by reading one file. Every function starts with an `_assert_*` guard.
"""

import os
from datetime import datetime

import frappe

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


# ---------------------------------------------------------------------------
# Fixture replay
# ---------------------------------------------------------------------------

#: Only these may be replayed. An unrestricted path here would be an arbitrary
#: file read dressed up as a feature.
REPLAYABLE_FIXTURES = ("auth_rfc3339.log", "auth_classic.log")


@frappe.whitelist(methods=["POST"])
def replay_fixture(name: str = "auth_rfc3339.log") -> dict:
	"""Ingest a checked-in log fixture as if it had just been logged.

	WHY THIS EXISTS. The development machine is WSL2 with no openssh-server, so
	it cannot produce a single real sshd event. Without this there would be no
	way to see the dashboard, the charts or the session correlation work before
	deploying to the real server — and "it compiles" is not evidence.

	Rows are tagged `ingest_source = "fixture"` so they are trivially
	distinguishable from real events, and `purge_fixture_events()` removes them.
	"""
	_assert_server_admin()
	_assert_developer_mode()

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
	stats = ingest.ingest_syslog_lines(lines, "fixture")
	frappe.db.commit()

	return {"fixture": name, "lines_in_file": len(raw_lines), **stats.as_dict()}


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
