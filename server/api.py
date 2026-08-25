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

from server import dashboard, system
from server.bench import commands as bench_commands
from server.bench import discovery, doctor, github, installer
from server.bench import logs as bench_logs
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

	# Only worth computing when it is about to matter — scanning every bench's
	# backup directory on every poll would be rude.
	report["backups"] = []
	if report["worst_level"] != "ok":
		for path in paths:
			report["backups"].extend(system.backup_usage(path))
		report["backups"].sort(key=lambda r: r["bytes"], reverse=True)
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


@frappe.whitelist()
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


@frappe.whitelist()
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

	if doc.status == "Queued":
		# Never picked up, so there is no process to kill and nothing has
		# happened yet. Close it out directly.
		doc.db_set(
			{"status": "Cancelled", "error_summary": "Cancelled before it started.", "exit_code": -1},
			update_modified=False,
		)
		if doc.is_restore():
			doc.clear_restore_secrets()
		frappe.db.commit()
		return {"name": name, "status": "Cancelled", "cancelled": True}

	frappe.cache.set_value(installer.CANCEL_KEY.format(name=name), 1, expires_in_sec=3600)
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

	doc.db_set({"status": "Queued", "error_summary": None}, update_modified=False)
	job_id = installer.enqueue_install_request(name)
	doc.db_set("job_id", job_id, update_modified=False)
	frappe.db.commit()
	return {"name": name, "status": "Queued", "job_id": job_id}


@frappe.whitelist(methods=["POST"])
def check_repo_access(git_url: str, branch: str | None = None) -> dict:
	"""Probe a remote without cloning it. Used by the form before submitting."""
	_assert_server_admin()
	return doctor.check_repo(git_url, branch)


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
