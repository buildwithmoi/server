# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Every whitelisted endpoint in this app, behind one shared guard.

House pattern: endpoints live in a single module rather than scattered across
doctype controllers, so the complete remotely-callable surface of the app can be
reviewed by reading one file. Every function starts with an `_assert_*` guard.
"""

import os
import re
import shutil
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import frappe

from server import dashboard, system
from server.bench import commands as bench_commands
from server.bench import discovery, doctor, github, installer
from server.bench import backups as bench_backups
from server.bench import inspect as bench_inspect
from server.bench import logs as bench_logs
from server.bench import siteconfig as bench_siteconfig
from server.bench import restore as bench_restore
from server.bench import ssl as bench_ssl
from server.geo import registry
from server.server.doctype.app_install_request.app_install_request import SSL_MODES
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
# GitHub profiles
# ---------------------------------------------------------------------------


@frappe.whitelist()
def list_github_profiles() -> list[dict]:
	"""Configured accounts. Never returns the token, only whether one is set."""
	_assert_server_admin()
	profiles = []
	for name in frappe.get_all("GitHub Profile", pluck="name", order_by="profile_name asc"):
		doc = frappe.get_doc("GitHub Profile", name)
		profiles.append(
			{
				"name": doc.name,
				"account": doc.account,
				"account_type": doc.account_type,
				"is_default": doc.is_default,
				"ssh_host_alias": doc.ssh_host_alias,
				"has_token": bool(doc.get_token()),
				"repo_count": doc.repo_count or 0,
				"last_synced_at": doc.last_synced_at,
				"sync_error": doc.sync_error,
			}
		)
	return profiles


@frappe.whitelist(methods=["POST"])
def save_github_profile(
	profile_name: str,
	account: str,
	account_type: str = "Organisation",
	access_token: str | None = None,
	ssh_host_alias: str | None = None,
	is_default: bool = False,
	name: str | None = None,
) -> dict:
	"""Create or update a profile.

	An omitted `access_token` LEAVES THE EXISTING ONE ALONE rather than clearing
	it. The UI never receives the token back, so it cannot send it again on an
	edit — treating "absent" as "delete it" would silently disconnect the
	profile every time someone renamed it.
	"""
	_assert_server_admin()

	doc = (
		frappe.get_doc("GitHub Profile", name)
		if name and frappe.db.exists("GitHub Profile", name)
		else frappe.new_doc("GitHub Profile")
	)
	doc.profile_name = profile_name
	doc.account = account
	doc.account_type = account_type
	doc.ssh_host_alias = ssh_host_alias
	doc.is_default = 1 if frappe.parse_json(is_default) else 0
	if access_token:
		doc.access_token = access_token
	doc.save()
	frappe.db.commit()
	return {"name": doc.name, "account": doc.account}


@frappe.whitelist(methods=["POST"])
def delete_github_profile(name: str) -> dict:
	_assert_server_admin()
	frappe.delete_doc("GitHub Profile", name)
	frappe.db.commit()
	return {"deleted": name}


@frappe.whitelist(methods=["POST"])
def sync_github_profile(name: str) -> dict:
	"""Refresh the cached repository list for one profile."""
	_assert_server_admin()
	return frappe.get_doc("GitHub Profile", name).sync_repos()


@frappe.whitelist()
def list_profile_repos(profile: str) -> list[dict]:
	"""Cached repositories, newest push first.

	Served from the cache so the picker filters as you type without a network
	round trip between each keystroke.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("GitHub Profile", profile)
	rows = [
		{
			"repo_name": r.repo_name,
			"default_branch": r.default_branch,
			"is_private": r.is_private,
			"is_archived": r.is_archived,
			"description": r.description,
			"pushed_at": r.pushed_at,
		}
		for r in doc.repos
	]
	# Python's sort is stable, so two obvious passes express this more clearly
	# than one clever composite key: newest push first, archived sunk to the
	# bottom rather than hidden, because occasionally an archived repo is
	# genuinely the one being looked for.
	rows.sort(key=lambda r: str(r["pushed_at"] or ""), reverse=True)
	rows.sort(key=lambda r: bool(r["is_archived"]))
	return rows


@frappe.whitelist()
def list_repo_branches(profile: str, repo: str) -> dict:
	"""Live branch list for a repository.

	Deliberately not cached: branches come and go constantly, and choosing one
	that no longer exists fails minutes into a clone instead of immediately.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("GitHub Profile", profile)
	try:
		branches, truncated = doc.branches(repo)
	except github.GitHubError as exc:
		return {"branches": [], "truncated": False, "default_branch": None, "error": str(exc)}

	default = next((r.default_branch for r in doc.repos if r.repo_name == repo), None)
	return {"branches": branches, "truncated": truncated, "default_branch": default, "error": None}


@frappe.whitelist()
def list_bench_apps(bench: str) -> list[dict]:
	"""Apps installed in a bench, for the Pull picker."""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	return [
		{
			"app_name": a.app_name,
			"branch": a.branch,
			"commit": a.commit,
			"git_url": a.git_url,
			"remote_name": a.remote_name,
			"is_dirty": a.is_dirty,
			"is_shallow": a.is_shallow,
		}
		for a in doc.apps
	]


# ---------------------------------------------------------------------------
# Bench management
# ---------------------------------------------------------------------------


@frappe.whitelist()
def list_benches() -> list[dict]:
	"""Every bench found on this machine, with its apps and sites."""
	_assert_server_admin()
	benches = frappe.get_all(
		"Server Bench",
		fields=[
			"name",
			"bench_path",
			"is_active",
			"frappe_branch",
			"python_version",
			"webserver_port",
			"socketio_port",
			"default_site",
			"shallow_clone",
			"last_scanned_at",
			"scan_error",
		],
		order_by="bench_name asc",
	)
	for bench in benches:
		doc = frappe.get_doc("Server Bench", bench["name"])
		bench["apps"] = [
			{
				"app_name": a.app_name,
				"branch": a.branch,
				"commit": a.commit,
				"git_url": a.git_url,
				"remote_name": a.remote_name,
				"is_shallow": a.is_shallow,
				"is_dirty": a.is_dirty,
			}
			for a in doc.apps
		]
		bench["sites"] = [
			{
				"site_name": s.site_name,
				"is_default": s.is_default,
				"installed_apps": (s.installed_apps or "").splitlines(),
			}
			for s in doc.sites
		]
	return benches


@frappe.whitelist()
def list_bench_commands() -> list[dict]:
	"""The catalogue of bench commands, including the ones we refuse to run.

	The unrunnable entries are returned deliberately. Someone searching for
	`console` should find it and be told why it cannot run here, rather than
	searching an apparently incomplete list.
	"""
	_assert_server_admin()
	return bench_commands.as_dicts()


@frappe.whitelist(methods=["POST"])
def run_bench_command(
	bench: str,
	command: str,
	site: str | None = None,
	params: dict | str | None = None,
	confirm: str | None = None,
) -> dict:
	"""Queue one catalogued bench command against a bench.

	A destructive command requires `confirm` to equal its label exactly. That is
	deliberately more friction than a checkbox: `drop-site` deletes a database
	and this app takes no backup first, so the interface should make it hard to
	do by accident and impossible to do by reflex.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	entry = bench_commands.get(command)
	if not entry:
		frappe.throw(f"{command!r} is not a known bench command.", title="Unknown Command")
	if not entry.runnable:
		frappe.throw(
			entry.unsupported_reason or f"{entry.label} cannot be run from here.", title="Not Runnable"
		)

	if entry.risk == bench_commands.RISK_DESTRUCTIVE and (confirm or "").strip() != entry.label:
		frappe.throw(
			f"{entry.label} can lose data and no backup is taken first. Type “{entry.label}” to "
			"confirm you meant it.",
			title="Confirmation Required",
		)

	values = frappe.parse_json(params) if isinstance(params, str) else (params or {})

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "Command",
			"bench": bench,
			"bench_command": command,
			"install_on_site": site,
			"command_params": frappe.as_json(values),
			"status": "Draft",
		}
	)
	doc.insert()
	frappe.db.commit()
	return run_install_request(doc.name)


@frappe.whitelist()
def site_config(bench: str, site: str) -> dict:
	"""A site's configuration, with every secret redacted.

	The same file holds `db_password` and `encryption_key`. Their presence is
	reported; their values never leave the server.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")
	report = bench_siteconfig.read(doc.bench_path, site)
	report["site"] = site
	report["bench"] = doc.name
	return report


@frappe.whitelist(methods=["POST"])
def update_site_config(bench: str, site: str, changes: dict | str) -> dict:
	"""Change one or more of the settings this app is willing to change.

	Only keys in the curated list are accepted, and each is coerced to the type
	frappe will read it back as — `maintenance_mode: "false"` is a non-empty
	string and therefore true, which is exactly the mistake worth designing out.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")

	wanted = frappe.parse_json(changes) if isinstance(changes, str) else (changes or {})
	if not wanted:
		frappe.throw("Nothing to change.")

	# Refuse to take THIS app's own site off the air from inside this app.
	#
	# Maintenance mode makes frappe return 503 for every request, including the
	# ones this interface makes — so turning it on here would work, and then
	# there would be no way to turn it off again short of an SSH session and a
	# text editor. Every other site on the bench is fair game.
	if site == frappe.local.site and frappe.parse_json(wanted.get("maintenance_mode") or 0):
		frappe.throw(
			f"{site} is the site this app runs on. Turning maintenance mode on here would take "
			"this interface down with it, and it could not be turned off again from inside. Use "
			f"<code>bench --site {site} set-config maintenance_mode 1</code> if you really mean it.",
			title="That Would Lock You Out",
		)

	try:
		result = bench_siteconfig.write(doc.bench_path, site, wanted)
	except bench_siteconfig.ConfigRefused as exc:
		frappe.throw(str(exc), title="Cannot Change This")

	frappe.logger("server").info(
		f"site config changed on {site}: {sorted(result['applied'])} by {frappe.session.user}"
	)
	report = bench_siteconfig.read(doc.bench_path, site)
	report["applied"] = result["applied"]
	report["backup"] = result["backup"]
	report["site"] = site
	return report


@frappe.whitelist()
def backup_plan(bench: str, site: str, keep: int = 5, older_than_days: float = 0) -> dict:
	"""What a prune would delete, without deleting anything.

	Always computed and shown before anything is removed. Deleting a backup
	breaks nothing today — you find out months later, when the one you wanted is
	the one that went.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")
	return bench_backups.plan(doc.bench_path, site, int(keep), float(older_than_days))


@frappe.whitelist(methods=["POST"])
def prune_backups(
	bench: str,
	site: str,
	keys: list | str,
	keep: int = 5,
	confirm: int | bool = 0,
) -> dict:
	"""Delete the named backup sets.

	The plan is recomputed inside `prune` rather than trusted from here: the
	browser chose these keys seconds ago, and a scheduled backup written in
	between would shift what "the newest five" means.
	"""
	_assert_server_admin()
	if not frappe.parse_json(confirm):
		frappe.throw(
			"Deleted backups cannot be recovered. Confirm before removing them.",
			title="Confirmation Required",
		)

	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")

	wanted = frappe.parse_json(keys) if isinstance(keys, str) else (keys or [])
	result = bench_backups.prune(doc.bench_path, site, list(wanted), int(keep))

	# An audit trail for a destructive action, in the app whose whole point is
	# knowing what happened on this server.
	# The health panel's breakdown is cached for five minutes, and the reason
	# anyone is here is that it said the disk was filling. Leaving it stale
	# means deleting gigabytes and being told nothing changed.
	frappe.cache.delete_value(BACKUP_USAGE_KEY)

	frappe.logger("server").info(
		f"pruned {len(result['deleted_sets'])} backup sets on {site} "
		f"({result['freed_text']}) by {frappe.session.user}"
	)
	return result


@frappe.whitelist()
def list_logs(bench: str) -> dict:
	"""Every log file this bench keeps, most recently written first."""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	files = bench_logs.list_logs(doc.bench_path, doc.site_names())
	return {"bench": doc.name, "files": [f.__dict__ for f in files]}


@frappe.whitelist()
def read_log(bench: str, path: str, lines: int = 300, search: str | None = None) -> dict:
	"""The tail of one log file, optionally filtered.

	The path comes from a browser, so it is checked against the bench's own log
	directories with resolved paths before anything is opened. A log reader that
	will read any file on the server is a file-disclosure hole, not a feature.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	roots = [directory for directory, _ in bench_logs.log_directories(doc.bench_path, doc.site_names())]

	if not bench_logs.is_inside(roots, path):
		frappe.throw(
			f"{path} is not one of {doc.name}'s log files.",
			title="Not A Log File",
		)

	result = bench_logs.tail(path, int(lines or 300), (search or "").strip() or None)
	result["path"] = path
	return result


@frappe.whitelist()
def recent_alerts(limit: int = 25) -> dict:
	"""Alerts raised for the current user.

	Frappe delivers these to the desk at /app, which is not where anyone using
	this app is looking. An alert nobody sees is the same as no alert at all —
	which was the original problem.
	"""
	_assert_server_admin()
	rows = frappe.get_all(
		"Notification Log",
		filters={"for_user": frappe.session.user, "type": "Alert"},
		fields=["name", "subject", "email_content", "creation", "read", "document_type", "document_name"],
		order_by="creation desc",
		limit=min(int(limit or 25), 100),
	)
	return {
		"alerts": rows,
		"unread": sum(1 for row in rows if not row.read),
	}


@frappe.whitelist(methods=["POST"])
def mark_alerts_read(name: str | None = None) -> dict:
	"""Mark one alert read, or all of them.

	Scoped to the current user's own rows in both cases — an endpoint that can
	mark someone else's notifications read is a small thing that becomes a way
	to hide an intrusion alert from whoever was meant to see it.
	"""
	_assert_server_admin()
	filters = {"for_user": frappe.session.user, "type": "Alert", "read": 0}
	if name:
		filters["name"] = name

	names = frappe.get_all("Notification Log", filters=filters, pluck="name")
	for row in names:
		frappe.db.set_value("Notification Log", row, "read", 1, update_modified=False)
	frappe.db.commit()
	return {"marked": len(names)}


#: Where the disk-pressure breakdown is cached, and for how long.
BACKUP_USAGE_KEY = "server:backup-usage"
BACKUP_USAGE_TTL = 300


@frappe.whitelist()
def security_events(
	severity: str | None = None,
	status: str | None = None,
	limit: int = 50,
) -> dict:
	"""Findings from the security detectors, newest first."""
	_assert_server_admin()
	filters = {}
	if severity:
		filters["severity"] = severity
	if status:
		filters["status"] = status

	rows = frappe.get_all(
		"Security Event",
		filters=filters,
		fields=[
			"name", "event_time", "severity", "category", "subject", "detail", "runbook",
			"status", "occurrences", "last_seen", "host",
		],
		order_by="event_time desc",
		limit=min(int(limit or 50), 200),
	)
	# Counted per severity with the query builder — frappe v16 refuses a SQL
	# function written as a string in `fields`.
	counts = frappe.get_all(
		"Security Event",
		filters={"status": "New"},
		fields=["severity", {"COUNT": "name", "as": "total"}],
		group_by="severity",
	)
	return {
		"events": rows,
		"open_by_severity": {row.severity: row.total for row in counts},
		"unreviewed_baseline": frappe.db.count("Persistence Item", {"status": "Active", "is_baseline": 0}),
	}


@frappe.whitelist(methods=["POST"])
def run_security_scan(record_only: int | bool = 0) -> dict:
	"""Run the persistence scan now.

	`record_only` stores the result without raising anything — the log-only
	mode for watching a detector for a week before letting it page anyone.
	"""
	_assert_server_admin()
	from server.security import watch

	return watch.scan(record_only=bool(frappe.parse_json(record_only)))


@frappe.whitelist(methods=["POST"])
def accept_security_baseline() -> dict:
	"""Mark everything currently recorded as reviewed and expected.

	Deliberately an explicit action. A server rebuilt from a snapshot of a
	compromised host would otherwise record that host's persistence as normal
	on its first scan and never mention it again.
	"""
	_assert_server_admin()
	from server.security import watch

	return watch.accept_baseline()


@frappe.whitelist(methods=["POST"])
def acknowledge_security_event(name: str, suppress_hours: int = 0, reason: str = "") -> dict:
	"""Acknowledge a finding, optionally silencing it for a while.

	Silence expires on its own and the reason is required to set one — there is
	no permanent suppression, because that is how alerting dies quietly.
	"""
	_assert_server_admin()
	hours = int(suppress_hours or 0)
	values = {
		"status": "Acknowledged",
		"acknowledged_by": frappe.session.user,
		"acknowledged_at": frappe.utils.now_datetime(),
	}
	if hours > 0:
		if not (reason or "").strip():
			frappe.throw("Say why it is being silenced.", title="Reason Required")
		values["status"] = "Suppressed"
		values["suppressed_until"] = frappe.utils.add_to_date(
			frappe.utils.now_datetime(), hours=min(hours, 24 * 30)
		)
		values["suppression_reason"] = reason.strip()

	frappe.db.set_value("Security Event", name, values, update_modified=False)
	frappe.db.commit()
	return {"name": name, "status": values["status"]}


@frappe.whitelist()
def system_health() -> dict:
	"""Disk, memory, load and where the disk went.

	Read-only and cheap enough to poll. Disk is the reason this exists: a full
	disk takes down every site on every bench at once, it fills slowly enough
	that nobody notices, and on a bench host the thing filling it is nearly
	always backups that were never cleared.
	"""
	_assert_server_admin()
	paths = frappe.get_all("Server Bench", filters={"is_active": 1}, pluck="bench_path")
	report = system.snapshot(paths)

	# Only worth computing when it is about to matter — and then cached, because
	# it is wanted precisely when the disk is under pressure and stat-ing every
	# backup file on a full disk every twenty seconds is the least helpful thing
	# this could do. Backups change on a schedule, so five minutes is fresh
	# enough to act on.
	report["backups"] = []
	if report["worst_level"] != "ok":
		cached = frappe.cache.get_value(BACKUP_USAGE_KEY)
		if cached is None:
			cached = []
			for path in paths:
				cached.extend(system.backup_usage(path))
			cached.sort(key=lambda r: r["bytes"], reverse=True)
			frappe.cache.set_value(BACKUP_USAGE_KEY, cached, expires_in_sec=BACKUP_USAGE_TTL)
		report["backups"] = cached
	return report


@frappe.whitelist()
def backup_usage(bench: str) -> dict:
	"""How much disk each site's backups are taking on one bench."""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	rows = system.backup_usage(doc.bench_path)
	return {
		"bench": doc.name,
		"rows": rows,
		"total": system.human(sum(r["bytes"] for r in rows)),
		"disk": (system.disk(doc.bench_path) or {}) and system.disk(doc.bench_path).__dict__,
	}


@frappe.whitelist()
def ssl_readiness(bench: str) -> dict:
	"""Everything the SSL dialog needs to tell you whether this will work.

	Read-only and deliberately synchronous — it is three filesystem reads and
	two short probes, and answering in the dialog is the entire point. The
	alternative is discovering that certbot is missing after nginx has already
	been stopped.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)

	sites = [{"name": row.site_name, "is_default": bool(row.is_default)} for row in doc.sites]
	report = bench_ssl.readiness(doc.bench_path, sites)
	report["bench"] = doc.name
	report["default_site"] = next((s["name"] for s in sites if s["is_default"]), None)
	return report


@frappe.whitelist(methods=["POST"])
def run_ssl(
	bench: str,
	mode: str,
	site: str | None = None,
	domain: str | None = None,
	dry_run: int | bool = 0,
) -> dict:
	"""Queue one SSL operation against a bench.

	Issuing takes a site offline for as long as certbot holds port 443, so it
	goes through the same queue, lock and streamed log as everything else rather
	than running inline in a web request.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	label = next((k for k, v in SSL_MODES.items() if v == mode), None) or mode
	if label not in SSL_MODES:
		frappe.throw(f"{mode!r} is not an SSL operation.", title="Unknown Operation")

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "SSL",
			"bench": bench,
			"ssl_mode": label,
			"ssl_domain": (domain or "").strip() or None,
			"ssl_dry_run": 1 if frappe.parse_json(dry_run) else 0,
			"install_on_site": site,
			"status": "Draft",
		}
	)
	doc.insert()
	frappe.db.commit()
	return run_install_request(doc.name)


@frappe.whitelist()
def list_backups(bench: str, site: str) -> dict:
	"""Backups this bench can restore from, newest first.

	Sets from other sites are included rather than filtered out — restoring
	production onto staging is a real thing to do — but each one carries the
	sentence explaining that it is from somewhere else.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")

	backups = bench_restore.list_backups(doc.bench_path, site)
	return {
		"site": site,
		"bench_path": doc.bench_path,
		"backups": [
			{
				**bench_restore.as_dict(b, site),
				"space": bench_restore.estimate_space(doc.bench_path, b).__dict__,
			}
			for b in backups
		],
		"searched": [path for path, _ in bench_restore.backup_directories(doc.bench_path, site)],
	}


@frappe.whitelist()
def list_restore_files(bench: str, site: str) -> dict:
	"""Files in the bench that could take part in a restore.

	For the case the bench directory exists to serve: a backup copied in from
	another server, whose three files have to be pointed at individually.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")

	return {
		"bench_path": doc.bench_path,
		"files": [f.__dict__ for f in bench_restore.list_files(doc.bench_path, site)],
	}


@frappe.whitelist()
def inspect_backup(
	bench: str,
	site: str,
	database_file: str | None = None,
	backup_key: str | None = None,
) -> dict:
	"""What apps this backup expects, and which ones the bench is missing.

	Read straight out of the dump's `tabInstalled Application` without loading
	anything. Restoring a database that references an app the bench does not
	have appears to succeed and leaves a broken site — every DocType belonging
	to the missing app is gone, and it surfaces later as import errors nobody
	connects back to the restore.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	if site not in doc.site_names():
		frappe.throw(f"{site!r} is not a site on {bench}.")

	config_file = None
	if backup_key:
		try:
			backup = bench_restore.find(doc.bench_path, site, backup_key)
		except bench_restore.RestoreRefused as exc:
			frappe.throw(str(exc), title="Cannot Read This Backup")
		database_file, config_file = backup.database, backup.site_config
	elif not database_file:
		frappe.throw("Nothing to inspect.")
	elif not bench_restore.is_inside(doc.bench_path, database_file):
		frappe.throw(f"{database_file} is not inside {doc.bench_path}.", title="Not Allowed")

	contents = bench_inspect.read_apps(database_file)
	contents.site_config_keys = bench_inspect.read_site_config(config_file)

	installed = {row.app_name: (row.branch or "") for row in doc.apps}
	report = bench_inspect.compare(contents, installed).as_dict()
	report["bench_apps"] = sorted(installed)
	return report


#: What may be uploaded into a bench. Anything else is not a backup.
UPLOAD_EXTENSIONS = (".sql", ".sql.gz", ".tar", ".tar.gz", ".tgz", ".json")

#: A name that will become a filename on the server, so it is matched rather
#: than escaped.
UPLOAD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")


#: Uploads arrive in pieces.
#:
#: frappe caps the request body at 25 MB for every path except its own
#: `/api/method/upload_file` (frappe/app.py), and it reads the whole body into
#: memory in `before_request` regardless — so a single-request upload of a real
#: dump was rejected with an HTML 413 before this endpoint's first line ran,
#: and raising the cap would only move the failure to the worker's RAM. Chunks
#: stay far below the limit and give the browser something real to show.
CHUNK_LIMIT = 16 * 1024 * 1024

#: Identifies one upload in progress. Becomes part of a filename.
UPLOAD_ID = re.compile(r"^[A-Za-z0-9]{8,64}$")

#: A part file older than this is abandoned and swept away.
PART_MAX_AGE = 24 * 3600


def _upload_target(bench_doc, name: str) -> tuple[str, str]:
	"""Where a named upload lands, and its in-progress partner."""
	directory = os.path.join(bench_doc.bench_path, "backups")
	os.makedirs(directory, exist_ok=True)
	return directory, os.path.join(directory, name)


def _validate_upload_name(raw: str) -> str:
	"""The uploaded name becomes a path on the server, so it is matched.

	Refused, not quietly renamed: `basename` alone would neutralise a traversal
	but save it under a different name, telling the operator nothing about what
	just happened. A filename containing a path was never a browser's own doing.
	"""
	raw = (raw or "").strip()
	name = os.path.basename(raw)
	if raw != name or "\\" in raw:
		frappe.throw(f"{raw!r} contains a path. Upload the file by name only.", title="Not A Plain Filename")
	if not UPLOAD_NAME.match(name) or not name.lower().endswith(UPLOAD_EXTENSIONS):
		frappe.throw(
			f"{name!r} is not a backup file. Upload the .sql.gz dump, or a files tar, exactly as "
			"frappe wrote it — the name is what tells this app which site and which backup it "
			"belongs to.",
			title="Not A Backup File",
		)
	return name


@frappe.whitelist(methods=["POST"])
def upload_backup_chunk(
	bench: str,
	upload_id: str,
	filename: str,
	chunk_index: int,
	total_chunks: int,
) -> dict:
	"""Receive one piece of a backup into the bench's drop zone.

	Appended to a `.part` file and renamed into place only when the last piece
	lands, so a half-uploaded file is never offered in the restore picker as
	though it were complete.

	Pieces must arrive in order. Accepting them out of order would mean either
	holding them all somewhere or seeking into a file whose final size is not
	yet known, and a browser has no reason to send them out of order.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	doc = frappe.get_doc("Server Bench", bench)
	name = _validate_upload_name(filename)
	if not UPLOAD_ID.match(upload_id or ""):
		frappe.throw("Bad upload id.", title="Upload Failed")

	index, total = int(chunk_index), int(total_chunks)
	if index < 0 or total < 1 or index >= total:
		frappe.throw("Bad chunk numbering.", title="Upload Failed")

	incoming = (frappe.request.files or {}).get("file") if frappe.request else None
	if incoming is None:
		frappe.throw("No data was uploaded.", title="Nothing Received")

	directory, target = _upload_target(doc, name)
	partial = os.path.join(directory, f".{upload_id}.part")

	if index == 0:
		if os.path.exists(target):
			frappe.throw(f"{name} is already in {directory}.", title="Already There")
		_sweep_stale_parts(directory)
		mode = "wb"
	else:
		if not os.path.exists(partial):
			frappe.throw(
				"This upload was interrupted. Start it again.", title="Upload Lost"
			)
		mode = "ab"

	try:
		with open(partial, mode) as handle:
			# Copied in blocks rather than read() in one go: the point of
			# chunking is that nothing holds a whole file in memory.
			shutil.copyfileobj(incoming.stream, handle, length=1024 * 1024)
	except OSError as exc:
		frappe.throw(f"Could not write the upload: {exc}", title="Upload Failed")

	if index + 1 < total:
		return {"received": index + 1, "of": total, "done": False}

	try:
		os.replace(partial, target)
	except OSError as exc:
		frappe.throw(f"Could not finish the upload: {exc}", title="Upload Failed")

	size = os.path.getsize(target)
	frappe.logger("server").info(
		f"uploaded {name} ({size} bytes, {total} chunks) to {bench} by {frappe.session.user}"
	)
	return {
		"received": total,
		"of": total,
		"done": True,
		"name": name,
		"path": target,
		"size": size,
		"size_text": system.human(size),
		"directory": directory,
	}


def _sweep_stale_parts(directory: str) -> None:
	"""Remove abandoned part files.

	A browser tab closed mid-upload leaves one behind, and they are invisible
	in the picker (the leading dot) — so without this they accumulate as disk
	nobody can account for, on the machine whose disk this app watches.
	"""
	cutoff = time.time() - PART_MAX_AGE
	try:
		entries = list(os.scandir(directory))
	except OSError:
		return
	for entry in entries:
		if not entry.name.endswith(".part"):
			continue
		try:
			if entry.stat().st_mtime < cutoff:
				os.unlink(entry.path)
		except OSError:
			continue


@frappe.whitelist()
def estimate_restore_space(
	bench: str,
	site: str,
	database_file: str,
	public_file: str | None = None,
	private_file: str | None = None,
) -> dict:
	"""Will this restore fit on the disk?

	Answered for hand-picked files, where there is no backup set to read the
	sizes from. Running out of disk part way through a restore leaves a
	half-loaded database on a full disk, which is worse than not starting.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", bench)
	try:
		backup = bench_restore.resolve_chosen(
			doc.bench_path, site, database_file, public_file, private_file
		)
	except bench_restore.RestoreRefused as exc:
		frappe.throw(str(exc), title="Cannot Restore")
	return bench_restore.estimate_space(doc.bench_path, backup).__dict__


@frappe.whitelist(methods=["POST"])
def run_restore(
	bench: str,
	site: str,
	db_root_password: str,
	backup_key: str | None = None,
	source: str = "Backup Set",
	database_file: str | None = None,
	public_file: str | None = None,
	private_file: str | None = None,
	db_root_username: str | None = None,
	encryption_key: str | None = None,
	with_public_files: int | bool = 0,
	with_private_files: int | bool = 0,
	backup_first: int | bool = 1,
	confirm: str | None = None,
) -> dict:
	"""Queue a restore.

	`confirm` must be the site name typed out. A restore drops the database and
	this app takes no automatic undo, so the confirmation is deliberately
	something you cannot do by reflex — the same bar as `drop-site`.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	if (confirm or "").strip() != site:
		frappe.throw(
			f"Restoring replaces everything in {site} and cannot be undone. "
			f"Type “{site}” to confirm you meant it.",
			title="Confirmation Required",
		)

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "Restore",
			"bench": bench,
			"install_on_site": site,
			"restore_source": source if source in ("Backup Set", "Chosen Files") else "Backup Set",
			"restore_backup_key": backup_key,
			"restore_database_file": (database_file or "").strip() or None,
			"restore_public_file": (public_file or "").strip() or None,
			"restore_private_file": (private_file or "").strip() or None,
			"restore_db_username": (db_root_username or "").strip() or None,
			"restore_db_password": db_root_password,
			"restore_encryption_key": (encryption_key or "").strip() or None,
			"restore_public_files": 1 if frappe.parse_json(with_public_files) else 0,
			"restore_private_files": 1 if frappe.parse_json(with_private_files) else 0,
			"restore_backup_first": 1 if frappe.parse_json(backup_first) else 0,
			"status": "Draft",
		}
	)
	doc.insert()
	frappe.db.commit()
	return run_install_request(doc.name)


@frappe.whitelist()
def get_bench(name: str) -> dict:
	"""One bench in full, plus the install history that targeted it."""
	_assert_server_admin()
	doc = frappe.get_doc("Server Bench", name)
	return {
		"name": doc.name,
		"bench_path": doc.bench_path,
		"is_active": doc.is_active,
		"exists_on_disk": doc.path_exists(),
		"frappe_branch": doc.frappe_branch,
		"python_version": doc.python_version,
		"frappe_user": doc.frappe_user,
		"shallow_clone": doc.shallow_clone,
		"webserver_port": doc.webserver_port,
		"socketio_port": doc.socketio_port,
		"redis_queue_port": doc.redis_queue_port,
		"redis_cache_port": doc.redis_cache_port,
		"default_site": doc.default_site,
		"last_scanned_at": doc.last_scanned_at,
		"scan_error": doc.scan_error,
		"notes": doc.notes,
		"apps": [
			{
				"app_name": a.app_name,
				"branch": a.branch,
				"commit": a.commit,
				"git_url": a.git_url,
				"remote_name": a.remote_name,
				"is_shallow": a.is_shallow,
				"is_dirty": a.is_dirty,
			}
			for a in doc.apps
		],
		"sites": [
			{
				"site_name": s.site_name,
				"is_default": s.is_default,
				"installed_apps": (s.installed_apps or "").splitlines(),
			}
			for s in doc.sites
		],
		"installs": frappe.get_all(
			"App Install Request",
			filters={"bench": name},
			fields=["name", "app_name", "branch", "status", "install_on_site", "creation"],
			order_by="creation desc",
			limit_page_length=10,
		),
	}


@frappe.whitelist(methods=["POST"])
def rescan_benches() -> dict:
	"""Rescan the bench root now."""
	_assert_server_admin()
	return discovery.scan_benches()


@frappe.whitelist()
def check_git_auth() -> dict:
	"""Read-only report on whether private clones will work from this machine."""
	_assert_server_admin()
	return doctor.check_git_auth()


@frappe.whitelist()
def list_install_requests(start: int = 0, page_length: int = 20) -> dict:
	"""Install history, newest first."""
	_assert_server_admin()
	return {
		"rows": frappe.get_all(
			"App Install Request",
			fields=[
				"name",
				"bench",
				"app_name",
				"branch",
				"status",
				"exit_code",
				"resolved_git_url",
				"install_on_site",
				"started_at",
				"finished_at",
				"duration",
				"error_summary",
				"creation",
			],
			order_by="creation desc",
			limit_start=max(int(start), 0),
			limit_page_length=min(max(int(page_length), 1), 100),
		),
		"total": frappe.db.count("App Install Request"),
	}


@frappe.whitelist(methods=["POST"])
def cancel_install_request(name: str) -> dict:
	"""Ask a running job to stop.

	Sets a flag the worker polls rather than reaching for the process directly:
	the process belongs to a worker in another OS process, and there is nothing
	in this one that could signal it.

	A job that has already finished is left alone — "cancel" arriving a second
	after "done" must not rewrite a successful run as cancelled.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("App Install Request", name)

	if doc.is_terminal():
		return {"name": name, "status": doc.status, "cancelled": False, "message": "Already finished."}

	# The flag goes up FIRST, and for a queued job as well as a running one.
	#
	# Queued used to close the row out without setting it, which left a race:
	# the worker can pick the job up between this reading "Queued" and writing
	# "Cancelled", after which nothing was watching and the job the operator
	# stopped ran to completion. run_install_request also checks this flag
	# before it writes status=Running, so setting it first closes that window
	# from both ends.
	key = installer.CANCEL_KEY.format(name=name)
	try:
		frappe.cache.set_value(key, 1, expires_in_sec=3600)
		flagged = frappe.cache.get_value(key) is not None
	except Exception:
		flagged = False

	if not flagged:
		# Read back rather than assumed. Without redis the worker has no way to
		# hear this, and saying "Stopping…" while nothing is would be worse than
		# saying so.
		frappe.log_error(f"could not set the cancel flag for {name}", "server: cancel")
		frappe.throw(
			"Could not reach Redis, so the job cannot be told to stop. It is still running. "
			"Check that the bench's redis-queue is up.",
			title="Cannot Stop This Job",
		)

	if doc.status == "Queued":
		# Not picked up yet, so there is no process to kill. Close it out
		# directly; the flag above covers the case where a worker takes it in
		# the meantime.
		doc.db_set(
			{
				"status": "Cancelled",
				"error_summary": "Cancelled before it started.",
				"exit_code": installer.NEVER_RAN,
				"finished_at": frappe.utils.now_datetime(),
			},
			update_modified=False,
		)
		if doc.is_restore():
			doc.clear_restore_secrets()
		frappe.db.commit()
		return {"name": name, "status": "Cancelled", "cancelled": True}

	return {
		"name": name,
		"status": doc.status,
		"cancelled": True,
		"message": "Stopping. The step that is running will be killed.",
	}


@frappe.whitelist()
def get_install_request(name: str) -> dict:
	"""One request with its full log.

	Polled by the UI while a job runs. Realtime events are published too, but
	polling is what makes the log correct after a page reload — a socket only
	carries what happened while you were listening.
	"""
	_assert_server_admin()
	doc = frappe.get_doc("App Install Request", name)
	return {
		"name": doc.name,
		"bench": doc.bench,
		"app_name": doc.app_name,
		"branch": doc.branch,
		"status": doc.status,
		"exit_code": doc.exit_code,
		"command": doc.command,
		"resolved_git_url": doc.resolved_git_url,
		"install_on_site": doc.install_on_site,
		"started_at": doc.started_at,
		"finished_at": doc.finished_at,
		"duration": doc.duration,
		"output": doc.output,
		"steps": frappe.parse_json(doc.steps) if doc.steps else [],
		"operation": doc.operation,
		"error_summary": doc.error_summary,
		"job_id": doc.job_id,
		"is_terminal": doc.is_terminal(),
	}


@frappe.whitelist(methods=["POST"])
def create_install_request(
	bench: str,
	operation: str = "Clone",
	source_type: str = "GitHub Profile",
	github_profile: str | None = None,
	repo: str | None = None,
	git_url: str | None = None,
	branch: str | None = None,
	app_name: str | None = None,
	install_on_site: str | None = None,
	skip_assets: bool = True,
	overwrite_existing: bool = False,
	force_install: bool = False,
	allow_merge: bool = False,
	run: bool = False,
) -> dict:
	"""Create a Clone or Pull request, optionally queueing it immediately."""
	_assert_server_admin()

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": operation,
			"bench": bench,
			"source_type": source_type,
			"github_profile": github_profile,
			"repo": repo,
			"git_url": git_url,
			"branch": branch,
			"app_name": app_name,
			"install_on_site": install_on_site,
			"skip_assets": 1 if frappe.parse_json(skip_assets) else 0,
			"overwrite_existing": 1 if frappe.parse_json(overwrite_existing) else 0,
			"force_install": 1 if frappe.parse_json(force_install) else 0,
			"allow_merge": 1 if frappe.parse_json(allow_merge) else 0,
			"status": "Draft",
		}
	)
	doc.insert()
	frappe.db.commit()

	if frappe.parse_json(run):
		return run_install_request(doc.name)
	return {
		"name": doc.name,
		"status": doc.status,
		"resolved_git_url": doc.resolved_git_url,
		"app_name": doc.app_name,
	}


@frappe.whitelist(methods=["POST"])
def run_install_request(name: str) -> dict:
	"""Queue a request for execution.

	The interlock is checked HERE, where there is a session and a user to
	refuse, as well as inside the job — where `frappe.only_for` cannot run
	because a worker has no session. Both checks are load-bearing: the setting
	can be switched off between queueing and execution.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	doc = frappe.get_doc("App Install Request", name)
	if doc.status in ("Queued", "Running"):
		frappe.throw(f"{name} is already {doc.status.lower()}.", title="Already Running")

	# Clear any cancel flag left from a previous attempt.
	#
	# It lives in redis for an hour, and the worker refuses to start a job that
	# is flagged — so re-running a request that was cancelled a few minutes ago
	# cancelled itself again, immediately, with a message about a worker that
	# had never picked it up.
	frappe.cache.delete_value(installer.CANCEL_KEY.format(name=name))

	doc.db_set(
		{"status": "Queued", "error_summary": None, "exit_code": installer.NEVER_RAN},
		update_modified=False,
	)
	job_id = installer.enqueue_install_request(name)
	doc.db_set("job_id", job_id, update_modified=False)
	frappe.db.commit()
	return {"name": name, "status": "Queued", "job_id": job_id}


@frappe.whitelist(methods=["POST"])
def check_repo_access(git_url: str, branch: str | None = None) -> dict:
	"""Probe a remote without cloning it. Used by the form before submitting.

	Behind the install interlock like every other endpoint that spawns a
	process. It was not, and that was the point: with Allow App Installs
	switched off — the app's stated kill switch for all subprocess activity —
	this path still ran `git`, and git takes options that name a command to
	run. `doctor.check_repo` now validates its own arguments, and this is the
	second lock on the same door.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()
	try:
		return doctor.check_repo(git_url, branch)
	except doctor.RepoRefused as exc:
		frappe.throw(str(exc), title="Cannot Probe This")


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
