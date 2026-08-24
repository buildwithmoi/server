# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Syncing what is on disk into Server Bench records."""

from __future__ import annotations

import frappe

from server.bench import scanner
from server.server.doctype.server_settings.server_settings import get_settings

SCAN_JOB_ID = "server::bench_scan"


def _apply(doc, info: scanner.BenchInfo) -> None:
	doc.bench_path = info.bench_path
	doc.is_active = 1
	doc.frappe_branch = info.frappe_branch
	doc.python_version = info.python_version
	doc.frappe_user = info.frappe_user
	doc.shallow_clone = 1 if info.shallow_clone else 0
	doc.webserver_port = info.webserver_port
	doc.socketio_port = info.socketio_port
	doc.redis_queue_port = info.redis_queue_port
	doc.redis_cache_port = info.redis_cache_port
	doc.default_site = info.default_site
	doc.last_scanned_at = frappe.utils.now_datetime()
	doc.scan_error = info.error

	# Child tables are rebuilt rather than merged. They are a snapshot of the
	# filesystem, not user data, and reconciling row-by-row would mean carrying
	# stale rows for apps that have since been removed.
	doc.set("apps", [])
	for app in info.apps:
		doc.append(
			"apps",
			{
				"app_name": app.app_name,
				"git_url": app.git_url,
				"remote_name": app.remote_name,
				"branch": app.branch,
				"commit": app.commit,
				"is_shallow": 1 if app.is_shallow else 0,
				"is_dirty": 1 if app.is_dirty else 0,
			},
		)

	doc.set("sites", [])
	for site in info.sites:
		doc.append(
			"sites",
			{
				"site_name": site.site_name,
				"installed_apps": "\n".join(site.installed_apps),
				"is_default": 1 if site.is_default else 0,
			},
		)


def scan_benches(root: str | None = None) -> dict:
	"""Rescan the bench root and update Server Bench records.

	Benches that have vanished from disk are marked inactive rather than
	deleted: an App Install Request that ran against one is history worth
	keeping, and deleting the bench would orphan its link.
	"""
	root = root or get_settings().get_bench_root()
	found = scanner.scan(root)
	seen = set()

	for info in found:
		seen.add(info.bench_name)
		name = frappe.db.exists("Server Bench", info.bench_name)
		doc = (
			frappe.get_doc("Server Bench", name)
			if name
			else frappe.get_doc({"doctype": "Server Bench", "bench_name": info.bench_name})
		)
		_apply(doc, info)
		doc.flags.ignore_permissions = True
		doc.save() if name else doc.insert(ignore_permissions=True)

	stale = frappe.get_all(
		"Server Bench", filters={"is_active": 1, "name": ("not in", seen or [""])}, pluck="name"
	)
	for name in stale:
		frappe.db.set_value("Server Bench", name, "is_active", 0, update_modified=False)

	frappe.db.commit()
	return {
		"root": root,
		"found": len(found),
		"deactivated": len(stale),
		"benches": sorted(b.bench_name for b in found),
	}


def enqueue_scan() -> None:
	"""Scheduler entry point."""
	frappe.enqueue(
		"server.bench.discovery.scan_benches",
		queue="long",
		timeout=600,
		job_id=SCAN_JOB_ID,
		deduplicate=True,
	)
