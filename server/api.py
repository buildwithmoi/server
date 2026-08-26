# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Every whitelisted endpoint in this app, behind one shared guard.

House pattern: endpoints live in a single module rather than scattered across
doctype controllers, so the complete remotely-callable surface of the app can be
reviewed by reading one file. Every function starts with an `_assert_*` guard.
"""

import hashlib
import hmac
import json
import os
import re
import shutil
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import frappe
import frappe.utils.password
from frappe.rate_limiter import rate_limit

from server import dashboard, system
from server.bench import commands as bench_commands
from server.bench import discovery, doctor, github, installer, scanner
from server.bench import provision as bench_provision
from server.bench import backups as bench_backups
from server.bench import inspect as bench_inspect
from server.bench import logs as bench_logs
from server.bench import siteconfig as bench_siteconfig
from server.bench import restore as bench_restore
from server.bench import ssl as bench_ssl
from server.geo import registry
from server.server.doctype.app_install_request.app_install_request import SSL_MODES
# Module level, not per-function. It was imported inside each caller, and the
# third one to need it simply forgot — which is a NameError at the moment the
# finding is raised, i.e. on the failure path, where it is least welcome.
from server.server.doctype.security_event.security_event import raise_event
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


@frappe.whitelist()
def server_settings_form() -> dict:
	"""Every setting, grouped the way the DocType groups them.

	Built from `frappe.get_meta` rather than from a list written out here. A
	hand-kept copy drifts: a field added to the DocType would simply not appear,
	and the only sign would be somebody wondering why the thing they read about
	is not on the page.

	NO SECRET IS EVER RETURNED. A Password field reports only whether one is
	set, which is the single fact the interface needs in order to say "leave
	blank to keep it".
	"""
	_assert_server_admin()

	settings = get_settings()
	meta = frappe.get_meta("Server Settings")

	groups: list[dict] = []
	current: dict | None = None

	for field in meta.fields:
		if field.fieldtype in ("Section Break", "Tab Break"):
			current = {"key": field.fieldname, "label": field.label or "General", "fields": []}
			groups.append(current)
			continue
		if field.fieldtype == "Column Break":
			continue
		if field.fieldtype in frappe.model.no_value_fields:
			continue
		if current is None:
			current = {"key": "general", "label": "General", "fields": []}
			groups.append(current)

		row = {
			"fieldname": field.fieldname,
			"label": field.label or field.fieldname,
			"fieldtype": field.fieldtype,
			"description": field.description or "",
			"options": [o for o in (field.options or "").split("\n") if o]
			if field.fieldtype == "Select"
			else None,
			"read_only": bool(field.read_only),
		}
		if field.fieldtype == "Password":
			# Never the value. `has_value` is what lets the field say "leave
			# blank to keep the one already there" without ever carrying it.
			row["has_value"] = bool(settings.get_password(field.fieldname, raise_exception=False))
			row["value"] = ""
		else:
			row["value"] = settings.get(field.fieldname)
		current["fields"].append(row)

	return {"groups": [g for g in groups if g["fields"]]}


@frappe.whitelist(methods=["POST"])
def save_server_settings(values: dict | str) -> dict:
	"""Write settings from the SPA.

	Only fields the DocType actually declares, and only ones it does not mark
	read-only — the payload comes from a browser, and "it is our own form" is
	not a reason to trust the shape of what arrives.

	A blank Password is "keep what is there", never "clear it". Sending an
	empty string for a secret is what a form does when it does not know the
	value, which is always — the form is never given it.
	"""
	_assert_server_admin()

	values = frappe.parse_json(values) if isinstance(values, str) else (values or {})
	meta = frappe.get_meta("Server Settings")
	editable = {
		field.fieldname: field
		for field in meta.fields
		if field.fieldtype not in frappe.model.no_value_fields and not field.read_only
	}

	doc = frappe.get_doc("Server Settings")
	written = []
	for name, value in values.items():
		field = editable.get(name)
		if not field:
			continue
		if field.fieldtype == "Password":
			if not (value or "").strip():
				continue
			doc.set(name, value)
		elif field.fieldtype == "Check":
			doc.set(name, 1 if frappe.parse_json(value) else 0)
		elif field.fieldtype == "Int":
			doc.set(name, frappe.utils.cint(value))
		else:
			doc.set(name, (value or "").strip() or None)
		written.append(name)

	doc.save(ignore_permissions=True)
	frappe.db.commit()
	# Settings are read through a cached document on every scheduled tick, so a
	# save nobody cleared would take effect at some unpredictable point later.
	frappe.clear_cache()
	return {"saved": written}


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


#: Methods this server is willing to forward to another. An allow-list, not a
#: blocklist: a proxy that forwards whatever it is handed is a remote shell
#: with extra steps, and this app already has one of those with a confirmation
#: box in front of it.
#:
#: Read methods are here so a switched console can render. Job-STARTING methods
#: are deliberately absent — `run_provision`, `run_restore`, `run_ssl` and the
#: terminal are not forwardable, because a destructive action taken against a
#: machine you only think you are looking at is the exact accident this feature
#: could otherwise cause. Switch to that server and run it there.
FORWARDABLE = frozenset(
	{
		"server.api.server_identity",
		"server.api.get_settings_summary",
		"server.api.get_health",
		"server.api.system_health",
		"server.api.get_overview",
		"server.api.list_benches",
		"server.api.get_bench",
		"server.api.list_bench_apps",
		"server.api.list_bench_commands",
		"server.api.list_backups",
		"server.api.list_restore_files",
		"server.api.backup_usage",
		"server.api.backup_plan",
		"server.api.site_config",
		"server.api.list_logs",
		"server.api.read_log",
		"server.api.security_events",
		"server.api.security_overview",
		"server.api.security_inventory",
		"server.api.ssh_sessions",
		"server.api.ssh_session_detail",
		"server.api.list_auth_events",
		"server.api.list_sudo_commands",
		"server.api.list_ip_addresses",
		"server.api.list_install_requests",
		"server.api.get_install_request",
		"server.api.deployment_logs",
		"server.api.deployment_log",
		"server.api.job_logs",
		"server.api.job_log",
		"server.api.ssl_readiness",
		# The two the cross-server restore needs.
		"server.api.prepare_backup_for_transfer",
		"server.api.transferable_backups",
		"server.api.remote_site_readiness",
		"server.api.plan_bench_migration",
		"server.api.bench_migration",
	}
)


@frappe.whitelist(methods=["POST"])
def start_bench_migration(
	server: str,
	remote_bench: str,
	target_bench: str,
	db_root_password: str,
	with_files: int | bool = 1,
	backup_first: int | bool = 1,
	confirm: str | None = None,
	renames: dict | str | None = None,
	domains: dict | str | None = None,
	domain_provider: str | None = None,
) -> dict:
	"""Move a whole bench here, as a chain of ordinary jobs.

	The plan is rebuilt at this moment rather than taken from the browser: what
	was shown a minute ago may not still be true, and acting on a stale plan is
	how a site gets overwritten that somebody created in between.

	`confirm` must equal the target bench name. This can replace existing sites
	and runs for hours.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	from server.remote import runner

	if (confirm or "").strip() != target_bench:
		frappe.throw(
			f"This moves every site on {remote_bench} and can run for hours. "
			f"Type “{target_bench}” to confirm.",
			title="Confirmation Required",
		)

	plan = plan_bench_migration(server, remote_bench, target_bench)

	# {source site: name to restore it as}. Every value is checked here rather
	# than at restore time: a bad one would otherwise surface as one failed job
	# in the middle of a chain that had already moved several sites.
	renames = frappe.parse_json(renames) if isinstance(renames, str) else (renames or {})
	for source_site, target_site in list(renames.items()):
		target_site = (target_site or "").strip()
		if not target_site or target_site == source_site:
			renames.pop(source_site)
			continue
		if not bench_provision.VALID_SITE_NAME.match(target_site):
			frappe.throw(
				f"{target_site!r} is not a usable site name. "
				"Lowercase letters, digits, dots and hyphens.",
				title="Bad Site Name",
			)
		renames[source_site] = target_site

	# {source site: the name it should answer to here}. Validated now for the
	# same reason the renames are: a bad one would otherwise surface as one
	# failed job in the middle of a chain that had already moved several sites.
	domains = frappe.parse_json(domains) if isinstance(domains, str) else (domains or {})
	for source_site, wanted in list(domains.items()):
		wanted = (wanted or "").strip().lower()
		if not wanted:
			domains.pop(source_site)
			continue
		if not bench_ssl.VALID_DOMAIN.match(wanted):
			frappe.throw(f"{wanted!r} is not a valid domain name.", title="Not a Domain")
		domains[source_site] = wanted

	actions = runner.build_actions(
		plan,
		with_files=bool(frappe.parse_json(with_files)),
		backup_first=bool(frappe.parse_json(backup_first)),
		renames=renames,
		domains=domains,
		domain_provider=(domain_provider or "").strip(),
	)
	if not actions:
		frappe.throw("There is nothing to move — that bench has no sites and no missing apps.",
		             title="Nothing To Do")

	doc = frappe.get_doc(
		{
			"doctype": "Bench Migration",
			"source_server": server,
			"source_bench": remote_bench,
			"target_bench": target_bench,
			"actions_json": frappe.as_json(actions),
			"with_files": 1 if frappe.parse_json(with_files) else 0,
			"backup_first": 1 if frappe.parse_json(backup_first) else 0,
			"current_action": 0,
			"status": "Planned",
		}
	)
	doc.db_password = db_root_password
	doc.insert()
	frappe.db.commit()

	raise_event(
		"Medium",
		"transfer",
		f"A whole-bench migration started: {remote_bench} → {target_bench}",
		f"{frappe.session.user} started moving {len(plan.get('sites', []))} site(s) from "
		f"{remote_bench} on {plan['source_server']} to {target_bench}. Recorded as {doc.name}.",
		"If you started it, no action. Each step is an ordinary job and appears in the "
		"deployment and restoration logs, so what it actually did is readable there.",
		source_doctype="Bench Migration",
		source_name=doc.name,
	)

	started = runner.start_next(doc.name)
	return {"name": doc.name, "actions": len(actions), "first": started}


@frappe.whitelist()
def list_bench_migrations(limit: int = 50) -> dict:
	"""Every bench move, so a paused one can be found again.

	Written because there was nowhere to go. The detail page existed and
	nothing linked to it: once the dialog was closed, a migration that had
	stopped halfway was unreachable, and the only apparent way forward was to
	start the whole thing again — re-cloning apps that were already there.
	"""
	_assert_server_admin()

	rows = frappe.get_all(
		"Bench Migration",
		fields=[
			"name", "status", "source_server", "source_bench", "target_bench",
			"current_action", "actions_json", "action_states", "notes",
			"creation", "started_at", "finished_at", "owner",
		],
		order_by="creation desc",
		limit=min(int(limit or 50), 200),
	)

	for row in rows:
		actions = frappe.parse_json(row.pop("actions_json") or "[]")
		states = frappe.parse_json(row.pop("action_states") or "[]")
		if len(states) != len(actions):
			# Same reconstruction the document does: everything before the
			# pointer is known to have succeeded.
			at = int(row.get("current_action") or 0)
			states = ["Success" if i < at else "Pending" for i in range(len(actions))]
		row["total"] = len(actions)
		row["done"] = sum(1 for state in states if state == "Success")
		row["failed"] = sum(1 for state in states if state == "Failed")

	return {
		"rows": rows,
		# The one that needs somebody. A paused move is not history — it is
		# work waiting to be continued.
		"unfinished": [r["name"] for r in rows if r["status"] in ("Running", "Paused")],
	}


@frappe.whitelist()
def bench_migration(name: str) -> dict:
	"""One migration, its actions, and where it has got to."""
	_assert_server_admin()

	doc = frappe.get_doc("Bench Migration", name)
	actions = doc.actions()
	jobs = frappe.get_all(
		"App Install Request",
		filters={"migration": name},
		fields=[
			"name", "operation", "app_name", "status", "started_at", "finished_at",
			# Why it stopped, on the page that shows it stopping. Without these
			# the migration view could say "Failed" and nothing else, and the
			# job holding the reason was three pages away — on whichever log
			# page happens to carry that operation.
			"error_summary", "exit_code", "bench", "install_on_site", "migration_action",
		],
		order_by="creation asc",
	)

	# Keyed by the action each job belongs to, not by position in this list.
	# Position was only ever true while every action produced exactly one job,
	# and an action already satisfied on disk now produces none — which slid
	# every later job up a row and attributed each one to the wrong step.
	by_action: dict[int, dict] = {}
	for order, job in enumerate(jobs):
		index = job.get("migration_action")
		by_action[int(index) if index is not None else order] = job
	# A migration that says Running while its current job has already failed.
	#
	# The chain is advanced from `installer.finish`, which calls
	# `on_job_finished` inside a try/except — Invariant 3 says nothing on the
	# way out of a job may raise. When that call is the thing that fails, the
	# job ends Failed, the migration is never told, and it sits at Running for
	# ever. The only record was a line in a log file nobody reads, and the
	# operator saw a failure notification over a page that said it was still
	# going.
	#
	# Repaired here, on read, because this is the page where the contradiction
	# is visible. Deliberately only the half that starts nothing: marking it
	# Paused is what makes Continue appear.
	if doc.status == "Running":
		index = int(doc.current_action or 0)
		current = jobs[index] if index < len(jobs) else None
		if current and current["status"] in ("Failed", "Cancelled"):
			doc.db_set("status", "Paused", update_modified=False)
			doc.db_set(
				"notes",
				f"Stopped at “{doc.describe(index)}” ({current['status']}). "
				f"Fix it and resume — everything before it is done.",
				update_modified=False,
			)
			frappe.db.commit()
			doc.reload()

	return {
		"name": doc.name,
		"status": doc.status,
		"source_server": doc.source_server,
		"source_bench": doc.source_bench,
		"target_bench": doc.target_bench,
		"current_action": doc.current_action,
		# Per action, so the page can show "this one failed and the two after
		# it succeeded" — which a single pointer cannot express, and which is
		# the whole shape of a batch of clones.
		"states": doc.states(),
		# Cleared on every terminal state, so Continue has to ask for it again
		# rather than failing after the button is pressed.
		"needs_password": not bool(doc.get_secret()),
		"failed": doc.failed_indexes(),
		"actions": actions,
		"jobs": jobs,
		"job_for_action": by_action,
		"notes": doc.notes,
	}


@frappe.whitelist(methods=["POST"])
def resume_bench_migration(name: str, db_root_password: str | None = None) -> dict:
	"""Continue a migration that stopped, from where it stopped.

	Not a restart. Everything before the failing action is real work — a bench
	built, sites already across — and redoing it would cost hours and would
	overwrite sites that moved correctly.

	CANCELLED COUNTS AS STOPPED. Stopping a move by hand ends the chain; it
	does not void the plan or undo the eight things it had done. Refusing to
	continue one meant the only way forward was a new migration, which is the
	thing this whole page exists to avoid. Only a move that SUCCEEDED has
	nothing left to do.

	The password is asked for again rather than being a dead end. It is cleared
	whenever a migration reaches a terminal state — deliberately, it is a
	database root password — and "it was cleared, start over" was an answer
	that cost an hour of cloning to work around.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	from server.remote import runner

	doc = frappe.get_doc("Bench Migration", name)
	if doc.status == "Success":
		frappe.throw(f"{name} finished — there is nothing to resume.", title="Not Resumable")

	if db_root_password:
		doc.db_set("db_password", db_root_password)
		frappe.db.commit()
		doc.reload()

	if not doc.get_secret():
		frappe.throw(
			"The database password was cleared when this migration stopped — it is a database "
			"root password and is never kept longer than a run needs it. Supply it again to "
			"continue: nothing already done is repeated.",
			title="Password Needed",
			exc=frappe.ValidationError,
		)

	# Retry what failed, in place. A clone that failed is stepped over during
	# the run so the rest of the batch finishes; Continue is where those get
	# another go — because Continue is pressed by somebody who has just fixed
	# something, and retrying only the failures is the difference between one
	# more clone and re-cloning six apps that are already there.
	retried = doc.failed_indexes()
	for index in retried:
		doc.set_state(index, doc.PENDING)
	if retried:
		doc.db_set(
			"notes",
			f"Retrying {len(retried)} that did not complete: "
			+ ", ".join(doc.describe(i) for i in retried),
			update_modified=False,
		)

	# Out of the terminal state before asking for the next action: `start_next`
	# refuses to touch a migration that is Cancelled, Success or Failed, so
	# resuming one without this returned "skipped" and did nothing at all.
	doc.db_set(
		{"status": "Running", "finished_at": None},
		update_modified=False,
	)
	frappe.db.commit()

	return runner.start_next(name)


@frappe.whitelist(methods=["POST"])
def cancel_bench_migration(name: str) -> dict:
	"""Stop a migration. The job currently running is left to finish.

	Killing a restore mid-flight leaves a site with a half-loaded database,
	which is worse than one extra site having moved.
	"""
	_assert_server_admin()

	doc = frappe.get_doc("Bench Migration", name)
	doc.finish("Cancelled", "Stopped by hand. Any job already running was left to finish.")
	return {"name": name, "status": "Cancelled"}


@frappe.whitelist()
def plan_bench_migration(server: str, remote_bench: str, target_bench: str | None = None) -> dict:
	"""What moving a whole bench here would involve, before any of it starts.

	Reads the bench there and the bench here and reports the difference: which
	apps have to be cloned first, which sites would be created and which
	replaced, and what order to do them in. Runs nothing.

	That separation is the point. Moving eight benches is a sequence of long
	jobs, and the useful thing is not to start them — it is to see, before
	starting any, what will be built and what is missing. A migration that
	stops forty minutes in because one repository is unreachable is the
	failure this exists to prevent.
	"""
	_assert_server_admin()

	from server.remote import migrate

	source = frappe.get_doc("Managed Server", server)
	answer = source.client().call("server.api.get_bench", {"name": remote_bench})
	if not answer.ok:
		frappe.throw(answer.error, title=f"{source.server_name} did not answer")

	target = (target_bench or remote_bench).strip()
	local = None
	if frappe.db.exists("Server Bench", target):
		local = get_bench(target)

	plan = migrate.build(
		source_server=source.server_name,
		remote_bench=answer.message or {},
		local_bench=local,
		target_bench_name=target,
	)
	return {
		**plan.as_dict(),
		# The label is for reading; the docname is what an action has to carry,
		# and two servers can legitimately share a display name.
		"source_server_name": source.name,
		"order": [s.site_name for s in migrate.order_sites(plan)],
	}


@frappe.whitelist()
def remote_site_readiness(server: str, remote_bench: str, remote_site: str, bench: str) -> dict:
	"""Which apps the site being moved needs, and whether this bench has them.

	Answered from the two benches' app lists rather than by reading a dump,
	which means it is answerable BEFORE anything is backed up or moved. That is
	the whole point: finding out that erpnext is missing after pulling four
	gigabytes is finding out too late.

	The dump is still checked later — `inspect.read_apps` reads the backup's own
	`tabInstalled Application` during the restore, and that is the authority.
	This is the early warning, and it is allowed to be slightly wrong in the
	direction of caution.
	"""
	_assert_server_admin()

	source = frappe.get_doc("Managed Server", server)
	answer = source.client().call("server.api.get_bench", {"name": remote_bench})
	if not answer.ok:
		frappe.throw(answer.error, title=f"{source.server_name} did not answer")

	remote = answer.message or {}
	site = next(
		(s for s in (remote.get("sites") or []) if s.get("site_name") == remote_site),
		None,
	)
	if not site:
		frappe.throw(f"{remote_site} is not a site on {remote_bench}.", title="Unknown Site")

	needed = [a for a in (site.get("installed_apps") or []) if a and a != "frappe"]
	remote_apps = {a["app_name"]: a for a in (remote.get("apps") or [])}

	here = frappe.get_doc("Server Bench", bench)
	local_apps = {a.app_name: a for a in (here.apps or [])}

	rows = []
	for app in needed:
		mine = local_apps.get(app)
		theirs = remote_apps.get(app, {})
		rows.append(
			{
				"app_name": app,
				"present": bool(mine),
				"source_branch": theirs.get("branch") or "",
				"local_branch": mine.branch if mine else "",
				"git_url": theirs.get("git_url") or "",
				# A branch difference is not a blocker — plenty of deployments
				# run the same app from different branches on purpose — but it
				# is the most common reason a restore succeeds and then behaves
				# oddly, so it is surfaced rather than hidden.
				"branch_matches": (not mine) or (not theirs.get("branch")) or mine.branch == theirs.get("branch"),
			}
		)

	# Whether that server will run anything for us. It is asked here, in the
	# dialog, rather than being discovered from a 403 after the job has started
	# and the plan has been shown — the interlock is off by default, so this is
	# the ordinary case for a server nobody has configured yet, not an edge one.
	identity = source.client().verify()

	return {
		"source_server": source.server_name,
		"remote_bench": remote_bench,
		"remote_site": remote_site,
		"bench": bench,
		"apps": rows,
		"missing": [r["app_name"] for r in rows if not r["present"]],
		"different_branch": [r["app_name"] for r in rows if r["present"] and not r["branch_matches"]],
		# None when the remote is too old to say. Absent must not read as off.
		"source_installs_allowed": (identity.data or {}).get("installs_allowed")
		if identity.ok
		else None,
	}


@frappe.whitelist()
def transferable_backups(bench: str, site: str) -> dict:
	"""What this server could hand to another one. Called BY a remote.

	Reuses the same discovery the local restore picker uses, so a backup that
	can be restored here is exactly a backup that can be pulled from here —
	there is no second notion of what counts as a usable set.
	"""
	_assert_server_admin()

	bench_doc = frappe.get_doc("Server Bench", bench)
	if site not in bench_doc.site_names():
		frappe.throw(f"{site} is not a site on {bench}.", title="Unknown Site")

	sets = bench_restore.list_backups(bench_doc.bench_path, site)
	return {
		"host": os.uname().nodename,
		"bench": bench,
		"site": site,
		"backups": [_transferable(b, site) for b in sets],
	}


def _transferable(backup, site: str) -> dict:
	"""A backup set, plus the size of EACH file in it.

	The set's own `size` is the total across every file, which is the right
	number for "will this fit on the disk" and the wrong one for "how many
	bytes should this download be". Using it as the target for a single part
	leaves the transfer short by exactly the other files — 343 bytes of site
	config, in the first case that caught this — and the client then reports a
	perfectly good backup as incomplete.
	"""
	parts = {}
	for part, path in (
		("database", backup.database),
		("public", backup.public_files),
		("private", backup.private_files),
		("config", backup.site_config),
	):
		if path and os.path.isfile(path):
			parts[part] = {"name": os.path.basename(path), "size": os.path.getsize(path)}

	return {**bench_restore.as_dict(backup, site), "parts": parts}


@frappe.whitelist(methods=["POST"])
def prepare_backup_for_transfer(bench: str, site: str, with_files: int | bool = 1) -> dict:
	"""Take a fresh backup here so another server can pull it. Called BY a remote.

	A FRESH one rather than the newest existing, because the point of moving a
	site is to move it as it is now — restoring last night's copy onto a new
	machine and calling the migration done is how a day of orders disappears.

	This runs synchronously and can take minutes on a large site. That is why
	`RemoteServer.CALL_TIMEOUT` is three minutes rather than the usual thirty
	seconds, and why the caller reports it as its own step.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	bench_doc = frappe.get_doc("Server Bench", bench)
	bench_doc.assert_usable()
	if site not in bench_doc.site_names():
		frappe.throw(f"{site} is not a site on {bench}.", title="Unknown Site")

	settings = get_settings()
	argv = bench_restore.build_backup_argv(
		settings.bench_executable, site, bool(frappe.parse_json(with_files))
	)

	import subprocess

	try:
		result = subprocess.run(  # noqa: S603
			argv,
			cwd=bench_doc.bench_path,
			env=settings.get_bench_env(),
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=settings.get_install_timeout(),
			check=False,
		)
	except subprocess.TimeoutExpired:
		frappe.throw(f"The backup of {site} did not finish in time.", title="Backup Timed Out")

	if result.returncode != 0:
		tail = (result.stdout or result.stderr or "").strip().splitlines()[-6:]
		frappe.throw(
			"bench backup failed on the source server: " + " / ".join(tail),
			title="Backup Failed",
		)

	sets = bench_restore.list_backups(bench_doc.bench_path, site)
	if not sets:
		frappe.throw(f"The backup finished but no set could be found for {site}.", title="Backup Missing")

	newest = sets[0]
	prepared = _transferable(newest, site)
	raise_event(
		"Medium",
		"transfer",
		f"A backup of {site} was prepared for another server",
		f"{frappe.session.user} asked this server for a fresh backup of {site} on {bench}, to be "
		f"pulled to another machine. Set {newest.key}.",
		"If you are moving this site, no action. If you did not ask for this, the API credentials "
		"for this server are in somebody else's hands — revoke that user's key and read the SSH "
		"and console records around this time.",
	)
	frappe.db.commit()

	return {"host": os.uname().nodename, "backup": prepared}


@frappe.whitelist()
def download_backup_file(bench: str, site: str, key: str, part: str = "database"):
	"""Stream one file out of a backup set. Called BY a remote, supports Range.

	WHY THIS IS SAFE TO EXPOSE, given it serves a database. It is whitelisted,
	so it is behind the same System Manager check as everything else and needs
	the API credentials to reach at all; the path is never taken from the
	caller, only a set key and a named part, both resolved against what this
	server itself discovered; and every download is recorded.

	Range support is not a nicety. A site backup is gigabytes, moving one
	between two machines will be interrupted, and without resume an
	interruption costs the whole transfer rather than the last few seconds.
	"""
	_assert_server_admin()

	bench_doc = frappe.get_doc("Server Bench", bench)
	backup = bench_restore.find(bench_doc.bench_path, site, key)

	path = {
		"database": backup.database,
		"public": backup.public_files,
		"private": backup.private_files,
		"config": backup.site_config,
	}.get(part)

	if not path or not os.path.isfile(path):
		frappe.throw(f"This backup has no {part} file.", title="Nothing To Send")

	# Belt and braces: the path came from our own discovery, but this is the
	# one endpoint that reads a file off disk on request, so it re-checks that
	# what it is about to send is inside the bench.
	if not bench_restore.is_inside(bench_doc.bench_path, path):
		frappe.throw("That file is not inside the bench.", title="Not Allowed")

	return _send_file_with_range(path)


#: The most this endpoint will put in one response. The transfer is driven by
#: the CLIENT asking for bounded ranges rather than the server streaming an
#: open-ended one, and that is not a stylistic choice: frappe builds a binary
#: response by holding `filecontent` in memory, so answering `bytes=0-` for a
#: four-gigabyte backup would try to allocate four gigabytes on a box with two
#: free. Bounded ranges cap both sides at this, and give resume for nothing.
TRANSFER_CHUNK = 8 * 1024 * 1024


def _send_file_with_range(path: str):
	"""Send one bounded slice of a file, as asked for by `Range`.

	WHY THE CLIENT IS TOLD THE SIZE ELSEWHERE, and not by a `Content-Range`
	header on this response. frappe's `as_binary()` builds a fresh `Response`
	from `filename` and `filecontent` alone — it discards `http_status_code`
	and any headers set on `frappe.local.response`. So a 206 and a
	`Content-Range` set here never reach the wire, and a client trusting them
	sees a plain 200 whose `Content-Length` is one chunk, concludes it has the
	whole file, and writes a truncated backup that only fails at restore.

	That is not a hypothetical: it is what the first version of this did.

	The size therefore travels in the JSON metadata the caller already fetches
	(`transferable_backups` / `prepare_backup_for_transfer`), and the client
	loops on that until it has every byte. This endpoint just serves the
	window it was asked for.
	"""
	size = os.path.getsize(path)
	raw = (frappe.request.headers.get("Range") or "").strip() if frappe.request else ""
	start, requested_end = 0, None

	if raw.startswith("bytes="):
		spec = raw[6:]
		if "," in spec:
			frappe.throw("Only one range at a time.", title="Range Not Supported")
		begin, _, end = spec.partition("-")
		try:
			start = int(begin) if begin else 0
			requested_end = int(end) if end else None
		except ValueError:
			start, requested_end = 0, None

	if start >= size and size:
		# Nothing left: the caller already has the file. An empty body is the
		# signal, since a 416 status would be discarded along with everything
		# else frappe drops from a binary response.
		frappe.local.response["type"] = "binary"
		frappe.local.response["filename"] = os.path.basename(path)
		frappe.local.response["filecontent"] = b""
		return

	last = size - 1 if size else 0
	end = min(requested_end if requested_end is not None else start + TRANSFER_CHUNK - 1, last)
	length = max(0, end - start + 1)

	with open(path, "rb") as handle:
		handle.seek(start)
		content = handle.read(length)

	frappe.local.response["type"] = "binary"
	frappe.local.response["filename"] = os.path.basename(path)
	frappe.local.response["filecontent"] = content


@frappe.whitelist()
def server_identity() -> dict:
	"""Who this machine is, for another server checking it can talk to us.

	The one endpoint a remote calls before trusting anything else. It answers
	"yes, this app is here and your key works" — which frappe's own `ping`
	cannot, because a frappe site without this app installed answers ping
	perfectly well and then fails at the first real call.
	"""
	_assert_server_admin()

	import server as app

	return {
		"app": "server",
		"version": getattr(app, "__version__", "") or "unknown",
		"hostname": os.uname().nodename,
		"site": frappe.local.site,
		"user": frappe.session.user,
		"benches": frappe.db.count("Server Bench", {"is_active": 1}),
		"time": str(frappe.utils.now_datetime()),
		# Whether this machine will actually RUN anything for a caller. Every
		# endpoint that spawns a process checks it, and it is off by default —
		# so a server can verify perfectly and then refuse the first real
		# request, which is a checkbox reported as a credentials problem.
		"installs_allowed": bool(get_settings().allow_app_install),
	}


@frappe.whitelist()
def list_managed_servers() -> list[dict]:
	"""Every server in the switcher. Never returns a secret — only that one exists."""
	_assert_server_admin()

	rows = frappe.get_all(
		"Managed Server",
		fields=[
			"name", "server_name", "base_url", "is_this_server", "verify_tls",
			"status", "last_verified_at", "remote_hostname", "remote_version", "verify_error",
			"api_key",
		],
		order_by="is_this_server desc, server_name asc",
	)
	for row in rows:
		row["has_secret"] = bool(
			frappe.utils.password.get_decrypted_password(
				"Managed Server", row["name"], "api_secret", raise_exception=False
			)
		)
	return rows


@frappe.whitelist(methods=["POST"])
def save_managed_server(
	name: str | None = None,
	server_name: str | None = None,
	base_url: str | None = None,
	api_key: str | None = None,
	api_secret: str | None = None,
	verify_tls: int | bool = 1,
	is_this_server: int | bool = 0,
) -> dict:
	"""Add or update a server.

	A blank secret on an edit means "keep the one you have", never "clear it" —
	the same rule as the GitHub and DNS credentials, and for the same reason:
	the form cannot show the existing value, so treating blank as a deletion
	would silently break the connection on every unrelated edit.
	"""
	_assert_server_admin()

	doc = frappe.get_doc("Managed Server", name) if name else frappe.new_doc("Managed Server")
	doc.server_name = (server_name or doc.server_name or "").strip()
	doc.base_url = (base_url or "").strip()
	doc.api_key = (api_key or "").strip()
	doc.verify_tls = 1 if frappe.parse_json(verify_tls) else 0
	doc.is_this_server = 1 if frappe.parse_json(is_this_server) else 0
	if api_secret:
		doc.api_secret = api_secret

	doc.flags.ignore_permissions = True
	doc.save()
	frappe.db.commit()
	return {"name": doc.name}


@frappe.whitelist(methods=["POST"])
def delete_managed_server(name: str) -> dict:
	_assert_server_admin()

	frappe.utils.password.remove_encrypted_password("Managed Server", name, "api_secret")
	frappe.delete_doc("Managed Server", name, ignore_permissions=True)
	frappe.db.commit()
	return {"deleted": name}


@frappe.whitelist(methods=["POST"])
def verify_managed_server(name: str) -> dict:
	"""Can this server reach that one, and are the keys right?"""
	_assert_server_admin()

	doc = frappe.get_doc("Managed Server", name)
	if doc.is_this_server:
		doc.record_check(True, identity=server_identity())
		return {"ok": True, "identity": server_identity(), "local": True}

	result = doc.client().verify()
	doc.record_check(result.ok, result.error, result.data if result.ok else {})
	frappe.db.commit()
	return {"ok": result.ok, "error": result.error, "identity": result.data if result.ok else {}}


@frappe.whitelist()
def call_remote(server: str, method: str, args: dict | str | None = None) -> dict:
	"""Forward one read-only call to another server and return its answer.

	The allow-list is the whole security model here. Without it this endpoint
	would let anyone with a session on THIS machine invoke any whitelisted
	method on every machine it holds keys for, which is a much larger hole
	than the one the switcher was meant to fill.
	"""
	_assert_server_admin()

	if method not in FORWARDABLE:
		frappe.throw(
			f"{method} is not forwarded to other servers. Read-only views are; anything that "
			f"starts a job is not, so a destructive action cannot be aimed at a machine you only "
			f"think you are looking at. Switch to that server and run it there.",
			title="Not Forwardable",
		)

	doc = frappe.get_doc("Managed Server", server)
	if doc.is_this_server:
		# Switching "to" the local machine is a no-op, not a loopback request.
		return {"ok": True, "message": frappe.call(method, **(frappe.parse_json(args) or {}))}

	values = frappe.parse_json(args) if isinstance(args, str) else (args or {})
	result = doc.client().call(method, values)

	if not result.ok:
		doc.record_check(False, result.error)
		frappe.db.commit()
		frappe.throw(result.error, title=f"{doc.server_name} did not answer")

	return {"ok": True, "message": result.message}


#: Which operations get a log page of their own, and what to call them. Both
#: read the same rows through the same renderer — a restore log that formatted
#: differently from a deployment log would be one more thing to learn when
#: something has already gone wrong.
LOG_KINDS = {
	"deployment": {"operation": "Provision", "label": "Bench Deployment"},
	"restore": {"operation": "Restore", "label": "Bench Restoration"},
	# Every remaining operation gets a page too. They already produce the same
	# transcript; without a page the only way to read one was the desk, which
	# is exactly the friction these logs exist to remove.
	"ssl": {"operation": "SSL", "label": "SSL Certificates"},
	"install": {"operation": ("Clone", "Pull"), "label": "App Installs"},
	"command": {"operation": ("Command", "Console"), "label": "Commands"},
}


#: How an Error Log row is recognised as this app's. frappe records every
#: unhandled exception from every app in one table, and a page showing all of
#: them would bury the ones that are ours under frappe's own — which are real
#: but are not what you are here to fix.
#:
#: Matched on the TRACEBACK, not on `method`. frappe's `method` column holds a
#: title rather than a code path — "Filelock: Failed to aquire …", "Page
#: serving not found" — so filtering on it found five of the twenty-two that
#: were actually ours. A stack that passes through `apps/server` is this app's,
#: whatever the row is called.
OURS = "%apps/server%"

_FRAME = re.compile(r'File "(?P<file>[^"]*apps/server/[^"]*)", line (?P<line>\d+), in (?P<func>\S+)')


@frappe.whitelist()
def scheduled_logs(start: int = 0, page_length: int = 50, failures_only: int | bool = 1) -> dict:
	"""How the background work is going, and what it said when it stopped.

	The detectors, the SSH ingest, geolocation and the digest all run on the
	scheduler, and until now a failure left a 500-character summary on the
	heartbeat and nothing else. frappe records the traceback in Scheduled Job
	Log; this joins it to the job type, because the log row names the type by
	its docname — `bb4l3kudhv` — which tells nobody anything.

	Failures only by default. There are hundreds of Complete rows an hour and
	they are not what anybody opens this page for.
	"""
	_assert_server_admin()

	ours = frappe.get_all(
		"Scheduled Job Type", filters={"method": ["like", "server.%"]}, fields=["name", "method"]
	)
	by_name = {row.name: row.method for row in ours}
	if not by_name:
		return {"rows": [], "total": 0, "failing": 0, "detectors": []}

	filters = {"scheduled_job_type": ["in", list(by_name)]}
	if frappe.parse_json(failures_only):
		filters["status"] = ["!=", "Complete"]

	rows = frappe.get_all(
		"Scheduled Job Log",
		filters=filters,
		fields=["name", "creation", "status", "scheduled_job_type", "details"],
		order_by="creation desc",
		start=int(start or 0),
		limit=min(int(page_length or 50), 200),
	)
	for row in rows:
		row["method"] = by_name.get(row["scheduled_job_type"], row["scheduled_job_type"])
		row["title"] = _last_exception_line(row.get("details") or "") or row["status"]
		# Scrubbed here as well as in the detail: a traceback carries locals,
		# and this is the same class of leak the crash log turned up.
		row["details"] = bench_siteconfig.scrub(row["details"] or "")

	return {
		"rows": rows,
		"total": frappe.db.count("Scheduled Job Log", filters),
		"failing": frappe.db.count(
			"Scheduled Job Log",
			{"scheduled_job_type": ["in", list(by_name)], "status": ["!=", "Complete"]},
		),
		# The detectors' own view of themselves, which is the other half of
		# "is the background work happening" — a job that never RAN leaves no
		# log row at all, and only the heartbeat notices that.
		"detectors": frappe.get_all(
			"Ingest Heartbeat",
			fields=["source", "last_run", "last_status", "last_error", "sequence", "expected_every"],
			order_by="source asc",
		),
	}


def _last_exception_line(text: str) -> str:
	"""The exception line out of a traceback, which is what identifies it."""
	# Indentation is the whole distinction, so it must NOT be stripped before
	# the test: every frame line and every source line in a traceback is
	# indented, and the exception is the one line that is not.
	for line in reversed((text or "").splitlines()):
		if not line.strip() or line[:1].isspace():
			continue
		if line.startswith(("File ", "Traceback")):
			continue
		return line.strip()[:200]
	return ""


@frappe.whitelist(methods=["POST"])
@rate_limit(key="client_error", limit=60, seconds=60 * 60, ip_based=True)
def report_client_error(
	message: str, stack: str | None = None, route: str | None = None, kind: str = "error"
) -> dict:
	"""Record a failure that happened in the browser.

	Everything else this app logs happens on the server. A Vue component that
	throws leaves nothing anywhere — the page goes blank or a panel stays empty,
	and the only record is a console the operator has already closed.

	Written into frappe's Error Log so it appears on the Crashes page beside
	the server-side ones, rather than inventing a second place to look.

	RATE LIMITED, and that is not incidental: this is a guest-shaped write path
	in the sense that anything running in the page can call it, and a component
	throwing in a render loop would otherwise write a row per frame until the
	disk filled.
	"""
	_assert_server_admin()

	title = f"Browser: {(message or 'error').strip()[:120]}"
	body = "\n".join(
		[
			f"Reported by the browser ({kind}).",
			f"Route: {route or 'unknown'}",
			f"User agent: {(frappe.request.headers.get('User-Agent') or '')[:200] if frappe.request else ''}",
			"",
			(stack or "(no stack)").strip()[:8000],
		]
	)

	frappe.get_doc(
		{
			"doctype": "Error Log",
			# The prefix is what makes these findable and, in the Crashes list,
			# distinguishable from a server failure at a glance.
			"method": title,
			"error": f"apps/server (browser)\n{bench_siteconfig.scrub(body)}",
		}
	).insert(ignore_permissions=True)
	frappe.db.commit()
	return {"recorded": True}


@frappe.whitelist()
def crash_logs(start: int = 0, page_length: int = 50, mine_only: int | bool = 1) -> dict:
	"""Unhandled failures, with the traceback frappe already recorded.

	WHY THIS PAGE EXISTS. Everything else in Logs is a job that ran and
	reported itself. This is the other kind of failure — the one where
	something threw where nobody was catching, and the only record is a row in
	frappe's Error Log at /app/error-log. There were twenty-two of this app's
	sitting there unreachable when this was written, including the filelock
	collision and the interlock refusals from building the migration.

	`mine_only` filters to this app by default. frappe logs its own failures in
	the same table, and while those are real they are not what somebody
	debugging a deployment is looking for.
	"""
	_assert_server_admin()

	filters = {"error": ["like", OURS]} if frappe.parse_json(mine_only) else {}

	rows = frappe.get_all(
		"Error Log",
		filters=filters,
		fields=["name", "creation", "method", "seen"],
		order_by="creation desc",
		start=int(start or 0),
		limit=min(int(page_length or 50), 200),
	)
	for row in rows:
		# A one-line summary for the list. The full traceback is fetched only
		# when a row is opened — they run to hundreds of lines each, and
		# sending fifty of them to render a list would be absurd.
		row["title"] = _crash_title(row["name"])

	return {
		"rows": rows,
		"total": frappe.db.count("Error Log", filters),
		"unseen": frappe.db.count("Error Log", {**filters, "seen": 0}),
	}


def _crash_title(name: str) -> str:
	"""The exception line, which is what identifies a crash at a glance."""
	error = frappe.db.get_value("Error Log", name, "error") or ""
	lines = [line.strip() for line in error.splitlines() if line.strip()]
	# The last line of a traceback is the exception and its message. Falling
	# back to the first is for the rows that are not tracebacks at all.
	for line in reversed(lines):
		if line and not line.startswith(("File ", "Traceback", "  ")):
			return line[:200]
	return (lines[0] if lines else "(empty)")[:200]


@frappe.whitelist()
def crash_log(name: str) -> dict:
	"""One crash, rendered the same way every other log here is.

	The transcript wrapper is not decoration: it means a traceback is copied
	out with the same button, in the same shape, as a deployment or a restore —
	so whoever receives it does not have to be told which kind of log it is.
	"""
	_assert_server_admin()

	doc = frappe.get_doc("Error Log", name)
	body = doc.error or ""
	# The deepest frame inside this app is what "where" actually means. The
	# `method` column is a title frappe made up — often the error message
	# itself — so printing it under a "Where" heading was answering the
	# question wrongly rather than not answering it.
	frames = _FRAME.findall(body)
	where = "—"
	if frames:
		path, line_no, func = frames[-1]
		where = f"{path.split('/apps/')[-1]}:{line_no} in {func}()"

	header = [
		"─" * 72,
		f"  {_crash_title(name)}",
		"─" * 72,
		"",
		f"{'Recorded':<18} {doc.creation}",
		f"{'Where':<18} {where}",
		f"{'Reported as':<18} {(doc.method or '—')[:90]}",
		f"{'Host':<18} {os.uname().nodename}",
		f"{'Reference':<18} {doc.name}",
		"",
		"─" * 72,
		"  Traceback",
		"─" * 72,
		"",
	]

	# Scrubbed on the way out. A traceback prints local variables, and this app
	# handles database root passwords and API secrets — `siteconfig.scrub` is
	# the same filter the job logs use, applied here because a crash is the one
	# place a secret reaches a log without anybody choosing to put it there.
	safe = "\n".join(bench_siteconfig.scrub(line) for line in body.splitlines())

	return {
		"name": doc.name,
		"title": _crash_title(name),
		"method": doc.method,
		"creation": str(doc.creation),
		"transcript": "\n".join(header) + safe + "\n",
		"filename": f"crash-{str(doc.creation)[:19].replace(' ', '_').replace(':', '')}-{doc.name}.txt",
	}


@frappe.whitelist()
def job_logs(
	kind: str = "deployment", start: int = 0, page_length: int = 50, status: str | None = None
) -> dict:
	"""One kind of job, newest first, with who ran it.

	`owner` is why these have a page separate from the Installs list: a
	deployment or a restore is the job somebody else usually has to read
	afterwards, and "which of us ran this" is the first question asked.
	"""
	_assert_server_admin()

	shape = LOG_KINDS.get(kind)
	if not shape:
		frappe.throw(f"There is no {kind!r} log.", title="Unknown Log")

	wanted = shape["operation"]
	filters = {"operation": ["in", list(wanted)] if isinstance(wanted, tuple) else wanted}
	if status:
		filters["status"] = status

	rows = frappe.get_all(
		"App Install Request",
		filters=filters,
		fields=[
			"name", "owner", "creation", "status", "exit_code", "operation",
			"bench", "install_on_site", "app_name",
			"provision_bench_name", "provision_site_name", "provision_frappe_version",
			"restore_source", "restore_remote_server", "restore_remote_site",
			"started_at", "finished_at", "duration", "error_summary",
		],
		order_by="creation desc",
		start=int(start or 0),
		limit=min(int(page_length or 50), 200),
	)

	counts = frappe.get_all(
		"App Install Request",
		filters={"operation": ["in", list(wanted)] if isinstance(wanted, tuple) else wanted},
		fields=["status", {"COUNT": "name", "as": "total"}],
		group_by="status",
	)

	return {
		"kind": kind,
		"label": shape["label"],
		"kinds": [{"kind": k, "label": v["label"]} for k, v in LOG_KINDS.items()],
		"rows": rows,
		"total": frappe.db.count("App Install Request", filters),
		"by_status": {row.status: row.total for row in counts},
	}


@frappe.whitelist()
def job_log(name: str) -> dict:
	"""One run, as a document that explains itself.

	Returns the transcript already rendered rather than the pieces, so the copy
	button, the download and anything that later attaches one to an alert all
	produce identical text.
	"""
	_assert_server_admin()

	from server.bench import transcript

	doc = frappe.get_doc("App Install Request", name)
	data = doc.as_dict()
	# `as_dict` includes the Password columns, which hold frappe's `*****`
	# placeholder rather than anything real — but they have no business in a
	# document built to be pasted into a chat window.
	for field in doc.SECRET_FIELDS:
		data.pop(field, None)
	data["host"] = os.uname().nodename

	steps = frappe.parse_json(doc.steps or "[]")
	return {
		"request": data,
		"steps": steps,
		"transcript": transcript.build(data, steps),
		"filename": transcript.filename(data),
	}


@frappe.whitelist()
def deployment_logs(start: int = 0, page_length: int = 50, status: str | None = None) -> dict:
	"""Every bench build, newest first, with who ran it.

	`owner` is a standard frappe column and is the whole reason this listing
	exists separately from the Installs view — a deployment is the one job
	somebody else usually has to read afterwards, and "which of us ran this"
	is the first question they ask.
	"""
	_assert_server_admin()

	filters = {"operation": "Provision"}
	if status:
		filters["status"] = status

	rows = frappe.get_all(
		"App Install Request",
		filters=filters,
		fields=[
			"name", "owner", "creation", "status", "exit_code",
			"provision_bench_name", "provision_site_name", "provision_frappe_version",
			"started_at", "finished_at", "duration", "error_summary",
		],
		order_by="creation desc",
		start=int(start or 0),
		limit=min(int(page_length or 50), 200),
	)

	counts = frappe.get_all(
		"App Install Request",
		filters={"operation": "Provision"},
		fields=["status", {"COUNT": "name", "as": "total"}],
		group_by="status",
	)

	return {
		"rows": rows,
		"total": frappe.db.count("App Install Request", filters),
		"by_status": {row.status: row.total for row in counts},
	}


@frappe.whitelist()
def deployment_log(name: str) -> dict:
	"""One build, as a document that explains itself.

	Returns the transcript already rendered rather than the pieces, so the
	copy button, the download and anything that later attaches one to an alert
	all produce the identical text. A log that differs depending on how it was
	obtained is one nobody can compare.
	"""
	_assert_server_admin()

	from server.bench import transcript

	doc = frappe.get_doc("App Install Request", name)
	if doc.operation != "Provision":
		frappe.throw(f"{name} is not a bench deployment.", title="Not A Deployment")

	data = doc.as_dict()
	# `as_dict` includes the Password columns, which hold frappe's `*****`
	# placeholder rather than anything real — but they have no business in a
	# document built to be pasted into a chat window.
	for field in doc.SECRET_FIELDS:
		data.pop(field, None)
	data["host"] = os.uname().nodename

	steps = frappe.parse_json(doc.steps or "[]")
	return {
		"request": data,
		"steps": steps,
		"transcript": transcript.build(data, steps),
		"filename": transcript.filename(data),
	}


@frappe.whitelist()
def provision_preflight(
	bench_name: str,
	site_name: str | None = None,
	frappe_version: str = "16",
	has_password: int | bool = 0,
) -> dict:
	"""Answer everything about a proposed bench before anything is spent.

	Called as the wizard is filled in, so it must be cheap and must not need
	the password itself — `has_password` is the tick, not the value. A password
	typed into a form should not travel to the server until the moment it is
	needed.
	"""
	_assert_server_admin()

	from server.bench import provision

	settings = get_settings()
	root = settings.get_bench_root()

	checks = provision.preflight(
		bench_root=root,
		bench_name=bench_name,
		site_name=site_name or "",
		db_root_password="x" if frappe.parse_json(has_password) else "",
		frappe_version=frappe_version,
	)

	used = frappe.get_all("Server Bench", filters={"is_active": 1}, pluck="webserver_port")
	try:
		index = provision.allocate_index([p for p in used if p])
		ports = provision.ports_for(index).as_dict()
		port_error = ""
	except provision.Refusal as exc:
		ports, port_error = {}, str(exc)

	return {
		"bench_root": root,
		"checks": [check.__dict__ for check in checks],
		"ready": all(check.ok for check in checks if check.blocking) and not port_error,
		"ports": ports,
		"port_error": port_error,
		"versions": list(provision.VERSIONS),
	}


@frappe.whitelist(methods=["POST"])
def run_provision(
	bench_name: str,
	frappe_version: str = "16",
	site_name: str | None = None,
	apps: list | str | None = None,
	db_root_password: str | None = None,
	admin_password: str | None = None,
	domain: str | None = None,
	domain_provider: str | None = None,
	skip_assets: int | bool = 1,
	confirm: str | None = None,
) -> dict:
	"""Queue the build of a new bench.

	`confirm` must equal the bench name. This spends several minutes and about
	four gigabytes, creates a database, and cannot be undone by pressing
	cancel — the row would stop, but a half-built bench stays on the disk.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	from server.bench import provision

	try:
		bench_name, site_name = provision.validate_names(bench_name, site_name or "")
	except provision.Refusal as exc:
		frappe.throw(str(exc), title="Cannot Build That")

	if (confirm or "").strip() != bench_name:
		frappe.throw(
			f"This builds a new bench and can take several minutes. Type “{bench_name}” to confirm.",
			title="Confirmation Required",
		)

	# Allocated here rather than in the job, so two requests queued in the same
	# minute cannot be handed the same block.
	used = frappe.get_all("Server Bench", filters={"is_active": 1}, pluck="webserver_port")
	try:
		index = provision.allocate_index([p for p in used if p])
	except provision.Refusal as exc:
		frappe.throw(str(exc), title="No Ports Left")

	chosen = frappe.parse_json(apps) if isinstance(apps, str) else (apps or [])
	lines = []
	for entry in chosen:
		if isinstance(entry, dict):
			lines.append(
				"|".join(
					[
						str(entry.get("profile") or ""),
						str(entry.get("repo") or ""),
						str(entry.get("branch") or ""),
					]
				)
			)

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "Provision",
			"provision_bench_name": bench_name,
			"provision_site_name": site_name,
			"provision_frappe_version": str(frappe_version),
			"provision_apps": "\n".join(lines),
			"provision_port_index": index,
			"provision_skip_assets": 1 if frappe.parse_json(skip_assets) else 0,
			"provision_domain": (domain or "").strip().lower() or None,
			"provision_domain_provider": domain_provider or None,
			"status": "Draft",
		}
	)
	if db_root_password:
		doc.provision_db_password = db_root_password
	if admin_password:
		doc.provision_admin_password = admin_password
	doc.insert()
	frappe.db.commit()
	return run_install_request(doc.name)


@frappe.whitelist()
def list_domain_providers() -> dict:
	"""Every stored registrar credential, without the credentials.

	`has_token` rather than the token, for the same reason GitHub Profile does
	it: this response reaches a browser, and a secret that reaches a browser is
	in its memory, its devtools and anything that can read either.
	"""
	_assert_server_admin()

	from server.domains import registry

	rows = frappe.get_all(
		"Domain Provider",
		fields=[
			"name", "provider_name", "provider", "is_default",
			"last_verified_at", "zone_count", "verify_error",
		],
		order_by="provider_name asc",
	)
	for row in rows:
		row["has_token"] = bool(
			frappe.utils.password.get_decrypted_password(
				"Domain Provider", row["name"], "api_token", raise_exception=False
			)
		)
		row["zones"] = frappe.get_all(
			"Domain Provider Zone",
			filters={"parent": row["name"], "parenttype": "Domain Provider"},
			pluck="zone",
			order_by="idx asc",
		)

	return {
		"providers": rows,
		"specs": [
			{
				"name": spec.name,
				"label": spec.label,
				"credential_label": spec.credential_label,
				"docs_url": spec.docs_url,
				"description": spec.description,
			}
			for spec in registry.get_provider_specs()
		],
	}


@frappe.whitelist(methods=["POST"])
def save_domain_provider(
	provider_name: str,
	provider: str,
	api_token: str | None = None,
	is_default: bool = False,
	name: str | None = None,
) -> dict:
	"""Create or update a credential.

	An omitted `api_token` LEAVES THE EXISTING ONE ALONE rather than clearing
	it — the same rule as GitHub Profile, and for the same reason: the browser
	never receives the token, so it cannot send it back on an edit, and reading
	"absent" as "delete" would disconnect the provider every time somebody
	renamed it or ticked the default box.
	"""
	_assert_server_admin()

	doc = (
		frappe.get_doc("Domain Provider", name)
		if name and frappe.db.exists("Domain Provider", name)
		else frappe.new_doc("Domain Provider")
	)
	doc.provider_name = provider_name
	doc.provider = provider
	doc.is_default = 1 if frappe.parse_json(is_default) else 0
	if api_token:
		doc.api_token = api_token
	doc.save()
	frappe.db.commit()
	return {"name": doc.name}


@frappe.whitelist(methods=["POST"])
def delete_domain_provider(name: str) -> dict:
	"""Remove a credential, and the secret with it.

	`remove_encrypted_password` explicitly: deleting the document drops the
	column, and the encrypted value would survive in `__Auth` — the trap this
	app documents and has been caught by before.
	"""
	_assert_server_admin()

	frappe.utils.password.remove_encrypted_password("Domain Provider", name, "api_token")
	frappe.delete_doc("Domain Provider", name, ignore_permissions=True)
	frappe.db.commit()
	return {"deleted": name}


@frappe.whitelist(methods=["POST"])
def verify_domain_provider(name: str) -> dict:
	"""Ask the provider what this credential can actually reach.

	A token that authenticates but holds none of the domains you meant is a
	common and specific mistake, so what comes back is the zone list rather
	than a tick.
	"""
	_assert_server_admin()
	return frappe.get_doc("Domain Provider", name).verify()


@frappe.whitelist()
def dns_records(name: str, zone: str) -> dict:
	"""Every record in one zone, as this app understands them.

	Read straight from the provider rather than from anything stored here. A
	cached copy of somebody else's DNS is a copy that is wrong the moment
	anyone edits it in the registrar's own console — which is where half of
	these records were made.
	"""
	_assert_server_admin()

	from server.domains import registry

	doc = frappe.get_doc("Domain Provider", name)
	result = registry.dispatch(doc.provider, doc.get_token() or "", "list_records", zone=zone)

	payload = result.as_dict()
	payload["zone"] = zone
	payload["provider"] = doc.provider
	payload["provider_name"] = doc.provider_name
	# What this machine believes its own address is, so a record pointing here
	# can be recognised without the operator holding it in their head.
	payload["this_host"] = _public_address()
	return payload


@frappe.whitelist(methods=["POST"])
def save_dns_record(
	name: str,
	zone: str,
	label: str,
	content: str,
	record_type: str = "A",
	ttl: int = 3600,
	confirm: str | None = None,
) -> dict:
	"""Create or replace one record.

	`confirm` must be the fully qualified name. Writing DNS for a live name is
	not reversible on anybody else's schedule — a wrong record propagates and
	is cached by resolvers that never asked this app's permission. Same bar as
	pointing a domain here, for the same reason.
	"""
	_assert_server_admin()

	from server.domains import base as domains_base
	from server.domains import registry

	label = (label or "").strip().rstrip(".").lower() or "@"
	zone = (zone or "").strip().rstrip(".").lower()
	fqdn = zone if label == "@" else f"{label}.{zone}"

	if (confirm or "").strip().lower() != fqdn:
		frappe.throw(
			f"This writes a public DNS record. Type “{fqdn}” to confirm.",
			title="Confirmation Required",
		)
	if not (content or "").strip():
		frappe.throw("A record needs a value to point at.", title="Nothing To Point At")

	doc = frappe.get_doc("Domain Provider", name)
	record = domains_base.DnsRecord(
		name=label,
		type=(record_type or "A").strip().upper(),
		content=(content or "").strip(),
		ttl=frappe.utils.cint(ttl) or domains_base.DEFAULT_TTL,
	)
	result = registry.dispatch(
		doc.provider, doc.get_token() or "", "upsert_record", zone=zone, record=record
	)

	raise_event(
		"Medium",
		"dns",
		f"DNS record written: {record.type} {fqdn} → {record.content}",
		f"Through {doc.provider_name} ({doc.provider}). Result: "
		+ ("written" if result.ok else f"refused — {result.error}"),
		"If this was not you, check who holds the API token for that provider and revoke it. "
		"A DNS record is how traffic for a name is redirected somewhere else entirely.",
	)
	frappe.db.commit()

	payload = result.as_dict()
	payload["fqdn"] = fqdn
	return payload


@frappe.whitelist(methods=["POST"])
def delete_dns_record(
	name: str, zone: str, label: str, record_type: str = "A", record_id: str = "",
	confirm: str | None = None,
) -> dict:
	"""Remove one record. Confirmed by name, like writing one."""
	_assert_server_admin()

	from server.domains import base as domains_base
	from server.domains import registry

	label = (label or "").strip().rstrip(".").lower() or "@"
	zone = (zone or "").strip().rstrip(".").lower()
	fqdn = zone if label == "@" else f"{label}.{zone}"

	if (confirm or "").strip().lower() != fqdn:
		frappe.throw(
			f"Removing {fqdn} takes it off the internet. Type “{fqdn}” to confirm.",
			title="Confirmation Required",
		)

	doc = frappe.get_doc("Domain Provider", name)
	record = domains_base.DnsRecord(
		name=label, type=(record_type or "A").strip().upper(), record_id=record_id or ""
	)
	result = registry.dispatch(
		doc.provider, doc.get_token() or "", "delete_record", zone=zone, record=record
	)

	raise_event(
		"High",
		"dns",
		f"DNS record removed: {record.type} {fqdn}",
		f"Through {doc.provider_name} ({doc.provider}). Result: "
		+ ("removed" if result.ok else f"refused — {result.error}"),
		"Removing a record takes the name off the internet. If this was not you, the API token "
		"for that provider should be treated as compromised and revoked.",
	)
	frappe.db.commit()

	payload = result.as_dict()
	payload["fqdn"] = fqdn
	return payload


@frappe.whitelist(methods=["POST"])
def point_domain_at_this_host(
	name: str, domain: str, address: str | None = None, confirm: str | None = None
) -> dict:
	"""Create or update the A record for `domain`, pointing here.

	`confirm` must equal the domain. Writing DNS for a live name is not
	reversible on anybody else's schedule — a wrong record propagates and is
	cached by resolvers that never asked this app's permission.
	"""
	_assert_server_admin()

	from server.bench import ssl as bench_ssl
	from server.domains import base as domains_base
	from server.domains import registry

	target = (domain or "").strip().rstrip(".").lower()
	if not bench_ssl.VALID_DOMAIN.match(target):
		frappe.throw(f"{domain!r} is not a valid domain name.", title="Not a Domain")

	if (confirm or "").strip().lower() != target:
		frappe.throw(
			f"This writes a public DNS record. Type “{target}” to confirm.",
			title="Confirmation Required",
		)

	doc = frappe.get_doc("Domain Provider", name)
	token = doc.get_token() or ""

	zones = doc.zone_names()
	if not zones:
		verified = doc.verify()
		if not verified["ok"]:
			return {"ok": False, "error": verified["error"]}
		zones = verified["zones"]

	zone, label = domains_base.split_domain(target, zones)
	if not zone:
		return {
			"ok": False,
			"error": (
				f"{target} is not inside any domain this credential manages "
				f"({', '.join(zones) or 'none'})."
			),
		}

	# The address this host is actually reachable on, unless one was given.
	# Guessing wrong here points a live name at the wrong machine, so the
	# caller can override it and the answer is reported back either way.
	chosen = (address or "").strip() or _public_address()
	if not chosen:
		return {
			"ok": False,
			"error": "Could not work out this host's public address. Supply one explicitly.",
		}

	record = domains_base.DnsRecord(name=label, content=chosen)
	result = registry.dispatch(doc.provider, token, "upsert_record", zone=zone, record=record)

	return {
		"ok": result.ok,
		"error": result.error,
		"detail": result.detail,
		"zone": zone,
		"label": label,
		"address": chosen,
		"domain": target,
	}


def _public_address() -> str:
	"""The address to point a domain at.

	Prefers a routable address over a private one. A bench behind NAT will
	report only private addresses, and pointing a public name at 10.x is a
	mistake worth refusing rather than making — so this returns nothing rather
	than a private address, and the caller says so.
	"""
	import ipaddress

	from server.bench import ssl as bench_ssl

	for candidate in sorted(bench_ssl.local_ips()):
		try:
			parsed = ipaddress.ip_address(candidate)
		except ValueError:
			continue
		if parsed.is_global:
			return candidate
	return ""


@frappe.whitelist()
def domain_readiness(bench: str, site: str, domain: str) -> dict:
	"""Everything between a DNS record and the site actually serving that name.

	THE POINT OF THIS ENDPOINT. Creating an A record is the visible step and the
	smallest one. Frappe also needs the domain added to the site, DNS
	multitenancy switched on, nginx regenerated and nginx reloaded — and two of
	those need root, which this app does not have. Reporting only "record
	created" would leave somebody waiting for a site that is never going to
	answer.

	Shaped like `ssl.readiness`: every question answered before anything is run,
	and each failure names the command that fixes it.
	"""
	_assert_server_admin()

	from server.bench import ssl as bench_ssl

	bench_doc = frappe.get_doc("Server Bench", bench)
	target = (domain or "").strip().rstrip(".").lower()

	dns = bench_ssl.dns_check(target) if target else {}
	multitenant = bench_ssl.is_dns_multitenant(bench_doc.bench_path)
	sudo_ok = bench_ssl.has_passwordless_sudo()
	_, existing = bench_ssl.site_domains(bench_doc.bench_path, site)

	checks = [
		bench_ssl.Check(
			key="dns",
			label="Resolves to this host",
			ok=bool(dns.get("points_here")),
			detail=dns.get("detail") or "Not resolving here yet. DNS changes take a few minutes.",
		),
		bench_ssl.Check(
			key="site_domain",
			label="Domain added to the site",
			ok=target in {d.lower() for d in existing},
			detail=(
				"Already added."
				if target in {d.lower() for d in existing}
				else f"Frappe will not serve a name it does not know about. Run: "
				f"bench setup add-domain --site {site} {target}"
			),
		),
		bench_ssl.Check(
			key="multitenant",
			label="DNS multitenancy",
			ok=multitenant,
			detail=(
				"Enabled."
				if multitenant
				else "Without it every domain on this bench serves the default site. "
				"Run: bench config dns_multitenant on"
			),
		),
		bench_ssl.Check(
			key="nginx",
			label="nginx can be reloaded",
			ok=sudo_ok,
			detail=(
				"Available."
				if sudo_ok
				else "Regenerating and reloading nginx needs root, and a background job has no "
				"terminal to type a password into. Run by hand: bench setup nginx && "
				"sudo bench setup reload-nginx"
			),
			# Advisory rather than blocking: the DNS record and the site
			# configuration are still worth doing without it, and the operator
			# finishing the last step by hand is a normal outcome here.
			blocking=False,
		),
	]

	return {
		"domain": target,
		"checks": [check.__dict__ for check in checks],
		"ready": all(check.ok for check in checks if check.blocking),
		"dns": dns,
	}


@frappe.whitelist(methods=["POST"])
def run_console_command(bench: str, command: str, confirm: str | None = None) -> dict:
	"""Run an arbitrary command in a bench directory, and record that it happened.

	THE CATALOGUE IS STILL THE DEFAULT. `run_bench_command` assembles a fixed
	argv from a validated entry and is what should be used for anything done
	twice. This is the escape hatch for the one-off, and it exists because the
	alternative was not "nobody runs arbitrary commands" — it was "somebody
	opens an SSH session and nothing records it".

	WHAT MAKES IT ACCEPTABLE is that it is loud rather than filtered. There is
	no blocklist: refusing `rm -rf /` while allowing a shell one-liner that does
	the same thing would imply a safety that does not exist. Instead the
	app-wide install switch gates it, and every command becomes a Security
	Event — hash-chained, forwarded off the box as it is written, and in the
	daily digest. An operator who wants to run something unrecorded still has
	to leave the app, which is the point.

	`confirm` must equal the bench name. Same reasoning as a destructive
	catalogue command: hard to do by accident, impossible by reflex.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	from server.bench import console as bench_console

	try:
		text = bench_console.validate(command)
	except bench_console.Refusal as exc:
		frappe.throw(str(exc), title="Cannot Run That")

	if (confirm or "").strip() != bench:
		frappe.throw(
			f"This runs a shell command as the bench user and every use is recorded. "
			f"Type “{bench}” to confirm you meant it.",
			title="Confirmation Required",
		)

	bench_doc = frappe.get_doc("Server Bench", bench)
	bench_doc.assert_usable()

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "Console",
			"bench": bench,
			"console_command": text,
			"status": "Draft",
		}
	)
	doc.insert()

	# Raised BEFORE the job is queued, so the record exists even if the worker
	# never picks it up or dies mid-command. A command that was attempted is
	# the fact worth keeping; whether it finished is on the request row.
	# THE SUBJECT CARRIES THE REQUEST NAME, AND THAT IS LOAD-BEARING.
	# `raise_event` dedupes on subject-plus-day, which is exactly right for a
	# standing condition — "disk is filling" should say so once a day, not once
	# a scan. It is exactly wrong for an audit trail. Verified by running five
	# different commands and finding ONE finding with occurrences=5, holding the
	# text of the first and no trace of the other four. An audit record that
	# silently merges distinct events is worse than none, because it looks
	# complete.
	raise_event(
		"Medium",
		"console",
		f"Shell command on {bench}: {bench_console.summarise(text, 50)} ({doc.name})",
		f"{frappe.session.user} ran, in {bench_doc.bench_path}:\n\n{bench_siteconfig.scrub(text)}\n\n"
		f"Recorded as {doc.name}, where the full output is kept.",
		"If you ran it, no action. If you did not, this is somebody with a System Manager "
		"session running shell commands as the bench user — treat the account as compromised, "
		"and read the output on the request row to see what they did. Turning off "
		"“Allow App Install” in Server Settings stops this and every other subprocess this "
		"app can start.",
		source_doctype="App Install Request",
		source_name=doc.name,
	)

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
	category: str | None = None,
	search: str | None = None,
	start: int = 0,
	page_length: int = 50,
	limit: int | None = None,
) -> dict:
	"""Findings from the security detectors, newest first.

	Paged, because eight detectors on a busy host produce more than a screen
	and a list that silently stops at fifty is a list that hides things.
	`limit` is still accepted so the dashboard's small preview keeps working.
	"""
	_assert_server_admin()

	filters = {}
	if severity:
		filters["severity"] = severity
	if status:
		filters["status"] = status
	if category:
		filters["category"] = category

	or_filters = None
	if search:
		# Subject and detail both, because "what was it about" is as often
		# remembered by the path inside the finding as by its title.
		term = f"%{search.strip()}%"
		or_filters = [["subject", "like", term], ["detail", "like", term]]

	page = min(int(limit or page_length or 50), 200)
	rows = frappe.get_all(
		"Security Event",
		filters=filters,
		or_filters=or_filters,
		fields=[
			"name", "event_time", "severity", "category", "subject", "detail", "runbook",
			"status", "occurrences", "last_seen", "host", "acknowledged_by", "acknowledged_at",
			"suppressed_until", "suppression_reason", "forwarded", "sequence",
		],
		order_by="event_time desc",
		start=int(start or 0),
		limit=page,
	)

	# Counted per severity with the query builder — frappe v16 refuses a SQL
	# function written as a string in `fields`.
	counts = frappe.get_all(
		"Security Event",
		filters={"status": "New"},
		fields=["severity", {"COUNT": "name", "as": "total"}],
		group_by="severity",
	)
	categories = frappe.get_all(
		"Security Event",
		fields=["category", {"COUNT": "name", "as": "total"}],
		group_by="category",
		order_by="category asc",
	)

	return {
		"events": rows,
		"total": frappe.db.count("Security Event", filters),
		"open_by_severity": {row.severity: row.total for row in counts},
		"categories": [{"category": row.category or "other", "total": row.total} for row in categories],
		"unreviewed_baseline": frappe.db.count("Persistence Item", {"status": "Active", "is_baseline": 0}),
	}


@frappe.whitelist()
def security_inventory(kind: str = "persistence", start: int = 0, page_length: int = 50) -> dict:
	"""What the detectors are watching, as opposed to what they found.

	The findings answer "what changed". This answers "what is there" — the
	units, accounts, keys, ports and files being compared against. Being able
	to read that list is most of what makes a baseline reviewable, and a
	baseline nobody reviews is one that quietly blesses whatever was already
	on the host.
	"""
	_assert_server_admin()

	shapes = {
		"persistence": ("Persistence Item", ["kind", "identifier", "path", "package", "package_owned", "status", "is_baseline", "last_seen"]),
		"accounts": ("System Account", ["username", "uid", "shell", "home", "can_log_in", "privileged", "groups", "password_status", "status", "is_baseline", "last_seen"]),
		"keys": ("Authorized Key", ["fingerprint", "key_type", "account", "comment", "options", "path", "status", "is_baseline", "last_seen"]),
		"sockets": ("Listening Socket", ["protocol", "local_address", "port", "process_name", "binary", "binary_verified", "pid", "listening_publicly", "status", "is_baseline", "last_seen"]),
		"files": ("Watched File", ["kind", "identifier", "path", "package", "package_owned", "status", "is_baseline", "last_seen"]),
	}
	if kind not in shapes:
		frappe.throw(f"Unknown inventory: {kind}", frappe.ValidationError)

	doctype, fields = shapes[kind]
	if not frappe.db.exists("DocType", doctype):
		return {"rows": [], "total": 0, "kind": kind, "doctype": doctype, "unreviewed": 0}

	return {
		"kind": kind,
		"doctype": doctype,
		"rows": frappe.get_all(
			doctype,
			filters={"status": "Active"},
			fields=["name", *fields],
			order_by="is_baseline asc, modified desc",
			start=int(start or 0),
			limit=min(int(page_length or 50), 200),
		),
		"total": frappe.db.count(doctype, {"status": "Active"}),
		"unreviewed": frappe.db.count(doctype, {"status": "Active", "is_baseline": 0}),
	}


@frappe.whitelist()
def ssh_sessions(start: int = 0, page_length: int = 50, status: str | None = None) -> dict:
	"""Logins, joined to the commands they ran.

	The attribution method travels with every row on purpose. An exact match
	on the audit session id and a guess from username-and-time must not look
	the same in a console, or the guess gets trusted like the measurement.
	"""
	_assert_server_admin()
	if not frappe.db.exists("DocType", "SSH Session"):
		return {"rows": [], "total": 0}

	filters = {"status": status} if status else {}
	return {
		"rows": frappe.get_all(
			"SSH Session",
			filters=filters,
			fields=[
				"name", "session_key", "status", "username", "source_ip", "country",
				"auth_method", "key_fingerprint", "login_time", "logout_time", "duration",
				"sudo_command_count", "attribution_method", "event_count", "hostname", "pid",
			],
			order_by="login_time desc",
			start=int(start or 0),
			limit=min(int(page_length or 50), 200),
		),
		"total": frappe.db.count("SSH Session", filters),
	}


@frappe.whitelist()
def ssh_session_detail(name: str) -> dict:
	"""One session, with the commands attributed to it."""
	_assert_server_admin()
	session = frappe.get_doc("SSH Session", name)
	return {
		"session": session.as_dict(),
		"commands": frappe.get_all(
			"SSH Sudo Command",
			filters={"ssh_session": name},
			fields=["name", "event_time", "actor", "target_user", "command", "status", "attribution_method", "tty", "pwd"],
			order_by="event_time asc",
			limit=500,
		),
		"events": frappe.get_all(
			"SSH Auth Event",
			filters={"session_key": session.session_key},
			fields=["name", "event_time", "event_type", "outcome", "auth_method", "raw_message"],
			order_by="event_time asc",
			limit=200,
		),
	}


@frappe.whitelist(methods=["POST"])
def run_security_scan(record_only: int | bool = 0) -> dict:
	"""Run the persistence scan now.

	`record_only` stores the result without raising anything — the log-only
	mode for watching a detector for a week before letting it page anyone.
	"""
	_assert_server_admin()
	from server.security import watch

	quiet = bool(frappe.parse_json(record_only))
	return {
		"persistence": watch.scan(record_only=quiet),
		"accounts": watch.scan_accounts(record_only=quiet),
		"network": watch.scan_network(record_only=quiet),
	}


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


@frappe.whitelist(allow_guest=True)
@rate_limit(key="security_heartbeat", limit=120, seconds=60 * 60, ip_based=True)
def security_heartbeat(token: str | None = None) -> dict:
	"""Is this host still watching itself? For a watcher somewhere else.

	Guest-accessible on purpose, gated by a shared token rather than a session:
	the whole value of this endpoint is that something OUTSIDE this machine can
	poll it, and requiring a login would mean managing a user for a monitor.

	A watcher that runs HERE cannot notice that it has been stopped. That is
	not a limitation to work around — it is why this endpoint exists. Point a
	second host at it, alert when `sequence` stops climbing, and alert equally
	loudly if it ever goes BACKWARDS, which means the database was replaced
	with an older copy.

	Returns counts and timings only. No finding text, because this is reachable
	without a session and a subject line can name an internal address.
	"""
	expected = get_settings().watchdog_secret()
	if not expected:
		frappe.throw("No watchdog token is configured.", frappe.PermissionError)
	if not token or not hmac.compare_digest(str(token), expected):
		# Constant-time, and deliberately the same message either way.
		frappe.throw("Not authorised.", frappe.PermissionError)

	beats = frappe.get_all(
		"Ingest Heartbeat",
		fields=["source", "last_run", "sequence", "expected_every", "last_status"],
	)
	now = frappe.utils.now_datetime()
	detectors = [
		{
			"source": beat.source,
			"sequence": beat.sequence,
			"expected_every": beat.expected_every,
			"status": beat.last_status,
			"seconds_since_last_run": (
				int(frappe.utils.time_diff_in_seconds(now, beat.last_run)) if beat.last_run else None
			),
		}
		for beat in beats
	]

	from server.server.doctype.ingest_heartbeat.ingest_heartbeat import overdue
	from server.server.doctype.security_event.security_event import head

	late = overdue()
	chain_sequence, chain_head = head()
	code_fingerprint = (
		frappe.db.get_value("Security Baseline", "selfcheck:code", "value_hash") or ""
	)

	payload = {
		"host": os.uname().nodename,
		"time": str(now),
		"healthy": not late and all(d["status"] == "OK" for d in detectors) and bool(detectors),
		"detectors": detectors,
		"overdue": late,
		# The sum climbs whenever any detector runs, so a single number is
		# enough for a simple watcher to alert on.
		"sequence_total": sum(d["sequence"] or 0 for d in detectors),
		"open_critical": frappe.db.count("Security Event", {"status": "New", "severity": "Critical"}),
		"open_high": frappe.db.count("Security Event", {"status": "New", "severity": "High"}),
		"undelivered": frappe.db.count("Security Event", {"forwarded": 0}),
		# The two values that let a watcher elsewhere check this host's own
		# records without trusting this host. `chain_head` is the tip of the
		# tamper-evident finding chain: it only ever moves forward, so a head
		# that CHANGES for a sequence already seen means history was rewritten.
		# `code_fingerprint` is a hash of this app's own source, so a detector
		# quietly edited to stop reporting shows up as a fingerprint that
		# changed with no deploy behind it.
		"chain_sequence": chain_sequence,
		"chain_head": chain_head,
		"code_fingerprint": code_fingerprint,
	}

	# Signed so the watcher can tell this host's answer from a convincing one.
	# Without a signature, anything able to intercept the request can return a
	# healthy payload forever — which is exactly what an intruder who has
	# noticed the polling would do. The nonce is the response time, which the
	# watcher already checks for staleness, so a captured reply cannot be
	# replayed tomorrow to prove today is fine.
	payload["signature"] = hmac.new(
		expected.encode(),
		json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
		hashlib.sha256,
	).hexdigest()
	return payload


@frappe.whitelist()
def security_overview() -> dict:
	"""What the detectors currently know, for the dashboard."""
	_assert_server_admin()
	open_counts = frappe.get_all(
		"Security Event",
		filters={"status": "New"},
		fields=["severity", {"COUNT": "name", "as": "total"}],
		group_by="severity",
	)
	return {
		"open_by_severity": {row.severity: row.total for row in open_counts},
		"persistence_items": frappe.db.count("Persistence Item", {"status": "Active"}),
		"accounts": frappe.db.count("System Account", {"status": "Active"}),
		"accounts_that_can_log_in": frappe.db.count(
			"System Account", {"status": "Active", "can_log_in": 1}
		),
		"keys": frappe.db.count("Authorized Key", {"status": "Active"}),
		"listening_ports": frappe.db.count("Listening Socket", {"status": "Active"}),
		"public_ports": frappe.db.count(
			"Listening Socket", {"status": "Active", "listening_publicly": 1}
		),
		"unreviewed": (
			frappe.db.count("Persistence Item", {"status": "Active", "is_baseline": 0})
			+ frappe.db.count("System Account", {"status": "Active", "is_baseline": 0})
			+ frappe.db.count("Listening Socket", {"status": "Active", "is_baseline": 0})
		),
		"last_scan": frappe.db.get_value(
			"Security Event", {}, "creation", order_by="creation desc"
		),
		"detectors": frappe.get_all(
			"Ingest Heartbeat",
			fields=["source", "last_run", "sequence", "last_status", "expected_every"],
		),
		"undelivered": frappe.db.count("Security Event", {"forwarded": 0}),
		"forwarding_configured": bool(get_settings().forwarding_target()[0]),
	}


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
	remote_server: str | None = None,
	remote_bench: str | None = None,
	remote_site: str | None = None,
	with_public_files: int | bool = 0,
	with_private_files: int | bool = 0,
	backup_first: int | bool = 1,
	confirm: str | None = None,
	domain: str | None = None,
	domain_provider: str | None = None,
	from_site: str | None = None,
) -> dict:
	"""Queue a restore.

	`confirm` must be the site name typed out — but ONLY when the target site
	already exists. A restore drops the database and this app takes no
	automatic undo, so the confirmation is deliberately something you cannot do
	by reflex, the same bar as `drop-site`. Restoring into a name this bench
	does not have destroys nothing, so demanding the ritual there is friction
	with no safety in it — and it is the safe habit: bring a backup up under a
	temporary name, check it, then swap.
	"""
	_assert_server_admin()
	get_settings().assert_installs_allowed()

	existing = frappe.get_doc("Server Bench", bench).site_names()
	replacing = site in existing

	if replacing and (confirm or "").strip() != site:
		frappe.throw(
			f"Restoring replaces everything in {site} and cannot be undone. "
			f"Type “{site}” to confirm you meant it.",
			title="Confirmation Required",
		)

	if not replacing and not bench_provision.VALID_SITE_NAME.match((site or "").strip()):
		frappe.throw(
			f"{site!r} is not a usable site name. Lowercase letters, digits, dots and hyphens.",
			title="Bad Site Name",
		)

	doc = frappe.get_doc(
		{
			"doctype": "App Install Request",
			"operation": "Restore",
			"bench": bench,
			"install_on_site": site,
			# An unknown source falls back to Backup Set rather than being
			# refused — but the list has to include every value the doctype
			# accepts, or a new one is silently downgraded here and the job
			# then looks for a local backup that was never chosen.
			"restore_source": source
			if source in ("Backup Set", "Chosen Files", "Remote Server")
			else "Backup Set",
			"restore_remote_server": remote_server or None,
			"restore_remote_bench": remote_bench or None,
			"restore_remote_site": remote_site or None,
			"restore_backup_key": backup_key,
			# Whose backup directory to read. Differs from the target only when
			# a backup is being brought up under another name.
			"restore_from_site": (from_site or "").strip() or None,
			"restore_database_file": (database_file or "").strip() or None,
			"restore_public_file": (public_file or "").strip() or None,
			"restore_private_file": (private_file or "").strip() or None,
			"restore_db_username": (db_root_username or "").strip() or None,
			"restore_db_password": db_root_password,
			"restore_encryption_key": (encryption_key or "").strip() or None,
			"restore_public_files": 1 if frappe.parse_json(with_public_files) else 0,
			"restore_private_files": 1 if frappe.parse_json(with_private_files) else 0,
			# A site that is not here has nothing to back up, and asking bench
			# to back one up that does not exist fails the job before the
			# restore is even attempted. Forced rather than trusted from the
			# browser: this is the API, and the dialog is one caller of it.
			"restore_backup_first": 1 if (replacing and frappe.parse_json(backup_first)) else 0,
			# The same two fields the provisioning wizard uses. A site being
			# created here needs pointing at exactly as much as one created
			# there, and a second pair of fields would only be a second thing
			# to keep in step.
			"provision_domain": (domain or "").strip() or None,
			"provision_domain_provider": (domain_provider or "").strip() or None,
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
def bench_root_report() -> dict:
	"""Where the scan looked, and what it rejected there.

	Exists because "no benches" and "wrong directory" looked identical. This app
	shipped a Bench Root default of the home directory it was written in, and
	the first server it was installed on displayed an empty page while holding
	twelve benches — with nothing on screen naming the path it had searched.
	"""
	_assert_server_admin()

	settings = get_settings()
	report = scanner.diagnose(settings.get_bench_root())
	# Named separately so the page can say "this came from Settings" versus
	# "this is where the app itself is installed" — which is the distinction an
	# operator needs in order to know what to change.
	report["configured"] = (settings.bench_root or "").strip()
	report["default_root"] = os.path.dirname(frappe.utils.get_bench_path().rstrip("/"))
	return report


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
				# `adoptRunningJobs` re-adopts from THIS listing after a page
				# reload, and the dock picks its verb from `operation`. Without
				# it every adopted job fell back to the default and a restore,
				# an SSL run and a bench build all displayed as "Cloning".
				"operation",
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
@frappe.whitelist(methods=["POST"])
def read_history(hours: int = 168) -> dict:
	"""Read further back than the first run did.

	The very first read looks back `bootstrap_hours` — 24 by default — and
	stores a cursor. Everything older than that window is never read, on a
	journal that on a normal Ubuntu box holds a week or more. The dashboard
	then drew those days as zeros, which is a claim about a quiet server rather
	than about an app that did not look.

	SAFE TO REPEAT, and not by luck: every row carries a UNIQUE dedup hash, so
	re-reading a window already read inserts nothing. That property is what the
	whole ingest design rests on — a crash between the two commits replays a
	window too.

	Drains in batches, because `max_records_per_run` is back-pressure against a
	brute-force burst and a week of one is more than a single batch.
	"""
	_assert_server_admin()

	hours = max(1, min(int(hours or 168), 24 * 90))
	settings = get_settings()
	if not settings.ssh_monitoring_enabled:
		frappe.throw("SSH monitoring is switched off.", title="Nothing To Read")

	# Forget where we are, so the next read starts from `hours` ago rather than
	# from the stored cursor. Everything in between is already held, and the
	# dedup hash discards it again.
	for row in frappe.get_all("Server Ingest Checkpoint", pluck="name"):
		checkpoint = frappe.get_doc("Server Ingest Checkpoint", row)
		checkpoint.reset_position()
		# reset_position() only mutates the document — inside the ingest its
		# caller goes on to save it. Here nothing else would, and without this
		# the stored cursor survives, `--since` is never passed, and the whole
		# backfill reads exactly nothing while reporting success.
		checkpoint.save(ignore_permissions=True)
	frappe.db.commit()

	inserted = read = batches = 0
	#: Bounded so a large window cannot loop until the request times out. Six
	#: batches of 5000 is 30,000 records — past a week of a brute-forced
	#: server — and the scheduler picks up any remainder on its own.
	for _ in range(6):
		result = ingest.run_ingest(since_hours=hours)
		batches += 1
		read += int(result.get("read") or 0)
		inserted += int(result.get("inserted") or 0)
		if not result.get("read"):
			break

	return {
		"hours": hours,
		"batches": batches,
		"read": read,
		"inserted": inserted,
		"collected_from": dashboard.collected_from(),
	}


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
