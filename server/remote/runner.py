# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Turning a migration plan into jobs, one at a time.

The plan says what has to happen. This starts the next thing and, when it
finishes, starts the one after — so a bench with eight sites is eight ordinary
restores rather than one enormous job nobody can interrupt or resume.

WHERE IT IS DRIVEN FROM. `installer.finish` is the single terminal point every
job passes through, whatever happened to it, so that is where the chain
advances. A path that returned early cannot leave a migration hanging, because
there is no early return that skips `finish`.

WHAT STOPS IT. A failed action stops the chain and leaves the migration Paused
rather than Failed. Paused is the honest word: the work already done is real —
the bench exists, four sites are across — and the useful next move is almost
always to fix the one thing and continue, not to start again. `resume` picks up
at `current_action`.
"""

from __future__ import annotations

import json

import frappe

#: What each action kind produces. Kept here rather than in the doctype so the
#: shapes and the code that builds them are in one file.
KIND_PROVISION = "provision"
KIND_CLONE = "clone"
KIND_RESTORE = "restore"


def build_actions(
	plan: dict,
	with_files: bool = True,
	backup_first: bool = True,
	renames: dict | None = None,
) -> list[dict]:
	"""The ordered list of jobs a plan implies.

	Order is not incidental. The bench has to exist before an app can be cloned
	into it, every app has to be there before a site that uses it is restored,
	and new sites go before replacements so an interruption leaves sites ADDED
	rather than half-overwritten.
	"""
	actions: list[dict] = []

	if not plan.get("bench_exists"):
		actions.append(
			{
				"kind": KIND_PROVISION,
				"label": f"Build {plan['target_bench']}",
				"bench_name": plan["target_bench"],
				"frappe_version": plan.get("frappe_version") or "16",
				# Every app the source bench has, cloned as part of the build.
				"apps": [
					{"repo": a["app_name"], "branch": a.get("branch") or "", "git_url": a.get("git_url") or ""}
					for a in plan.get("apps", [])
				],
			}
		)
	else:
		for app in plan.get("apps", []):
			if app.get("present"):
				continue
			actions.append(
				{
					"kind": KIND_CLONE,
					"label": f"Clone {app['app_name']}",
					"bench": plan["target_bench"],
					"repo": app["app_name"],
					"branch": app.get("branch") or "",
					"git_url": app.get("git_url") or "",
				}
			)

	ordered = sorted(
		plan.get("sites", []), key=lambda s: (bool(s.get("exists_here")), s.get("site_name", ""))
	)
	renames = renames or {}
	for site in ordered:
		source_site = site["site_name"]
		# The target name may differ from the source: bringing a site up beside
		# the live one under a temporary name, checking it, and swapping later
		# is the safe way to move a site, and it needs the two names to be
		# separate values rather than one repeated twice.
		target_site = (renames.get(source_site) or source_site).strip()
		renamed = target_site != source_site
		actions.append(
			{
				"kind": KIND_RESTORE,
				"label": f"Move {source_site} → {target_site}" if renamed else f"Move {source_site}",
				"bench": plan["target_bench"],
				"site": target_site,
				"remote_server": plan["source_server_name"],
				"remote_bench": plan["source_bench"],
				"remote_site": source_site,
				"with_files": bool(with_files),
				# A site that does not exist here has nothing to back up, so
				# the option only means anything for a replacement — and a
				# renamed target never exists here.
				"backup_first": bool(backup_first and site.get("exists_here") and not renamed),
			}
		)

	return actions


def start_next(migration_name: str) -> dict:
	"""Queue the action at `current_action`, or finish the migration.

	Returns what it did, so a caller can report it. Never raises out to a
	worker: this runs from `installer.finish`, and an exception there would
	surface from inside the handler reporting the job that just ended.
	"""
	from server import api

	try:
		migration = frappe.get_doc("Bench Migration", migration_name)
	except frappe.DoesNotExistError:
		return {"error": f"{migration_name} is gone"}

	if migration.status in ("Cancelled", "Success", "Failed"):
		return {"skipped": migration.status}

	actions = migration.actions()
	index = int(migration.current_action or 0)

	if index >= len(actions):
		migration.finish("Success", f"All {len(actions)} actions completed.")
		return {"done": True, "actions": len(actions)}

	action = actions[index]
	password = migration.get_secret()

	try:
		if action["kind"] == KIND_PROVISION:
			result = api.run_provision(
				bench_name=action["bench_name"],
				frappe_version=action.get("frappe_version") or "16",
				site_name=None,
				apps=[
					{"profile": "", "repo": a["repo"], "branch": a.get("branch") or ""}
					for a in action.get("apps", [])
				],
				db_root_password=None,
				confirm=action["bench_name"],
			)
		elif action["kind"] == KIND_CLONE:
			result = api.create_install_request(
				bench=action["bench"],
				operation="Clone",
				source_type="Git URL",
				git_url=action.get("git_url") or "",
				branch=action.get("branch") or "",
				app_name=action["repo"],
				run=True,
			)
		else:
			result = api.run_restore(
				bench=action["bench"],
				site=action["site"],
				source="Remote Server",
				remote_server=action["remote_server"],
				remote_bench=action["remote_bench"],
				remote_site=action["remote_site"],
				db_root_password=password,
				with_public_files=1 if action.get("with_files") else 0,
				with_private_files=1 if action.get("with_files") else 0,
				backup_first=1 if action.get("backup_first") else 0,
				confirm=action["site"],
			)
	except Exception as exc:  # noqa: BLE001
		migration.db_set("status", "Paused", update_modified=False)
		migration.db_set(
			"notes", f"Could not start “{action['label']}”: {exc}"[:1000], update_modified=False
		)
		frappe.db.commit()
		return {"error": str(exc)}

	request = result.get("name") if isinstance(result, dict) else None
	migration.db_set(
		{"status": "Running", "started_at": migration.started_at or frappe.utils.now_datetime()},
		update_modified=False,
	)
	frappe.db.commit()
	return {"started": request, "action": action["label"], "index": index}


def on_job_finished(request_name: str, status: str) -> None:
	"""Called from `installer.finish` for every job, migration or not.

	Cheap for the common case: one indexed lookup that finds nothing.
	"""
	from server.server.doctype.bench_migration.bench_migration import CONTINUE_ON

	migration_name = frappe.db.get_value(
		"App Install Request", request_name, "migration"
	)
	if not migration_name:
		return

	try:
		migration = frappe.get_doc("Bench Migration", migration_name)
	except frappe.DoesNotExistError:
		return

	if migration.status in ("Cancelled", "Success", "Failed"):
		return

	index = int(migration.current_action or 0)
	label = migration.describe(index)

	if status not in CONTINUE_ON:
		# Paused, not Failed. The bench and the sites already moved are real
		# work, and the useful next move is nearly always to fix one thing and
		# continue rather than to start the whole migration again.
		migration.db_set("status", "Paused", update_modified=False)
		migration.db_set(
			"notes",
			f"Stopped at “{label}” ({status}). Fix it and resume — everything before it is done.",
			update_modified=False,
		)
		frappe.db.commit()
		return

	migration.db_set("current_action", index + 1, update_modified=False)
	frappe.db.commit()
	start_next(migration_name)


def reconcile_migrations() -> dict:
	"""Unstick a migration whose job finished without telling it.

	`on_job_finished` runs inside `installer.finish`, wrapped, because nothing
	on the way out of a job may raise (Invariant 3). The cost of that wrapping
	is that when the advance itself fails — a deadlock on the row, a worker
	killed between the two commits — the job ends and the migration is never
	told. It then says Running for ever, the Continue button never appears
	because that only shows for Paused, and the only trace is a line in a log
	file nobody reads.

	So the state is derived rather than trusted, on a schedule. This is the
	half that `bench_migration` deliberately does not do: it starts the next
	job, which is a side effect that has no business happening on a page load.
	"""
	repaired = []
	for row in frappe.get_all("Bench Migration", filters={"status": "Running"}, pluck="name"):
		try:
			migration = frappe.get_doc("Bench Migration", row)
			index = int(migration.current_action or 0)
			jobs = frappe.get_all(
				"App Install Request",
				filters={"migration": row},
				fields=["name", "status"],
				order_by="creation asc",
			)
			current = jobs[index] if index < len(jobs) else None
			if not current:
				# Nothing has been started for the current action. Either it is
				# about to be, or the start was lost — starting it again is
				# safe, because start_next refuses when a job already exists.
				start_next(row)
				repaired.append(f"{row}: restarted the chain")
				continue

			if current["status"] in ("Queued", "Running"):
				continue

			# Terminal. Whatever the outcome, the migration should have been
			# told about it and was not.
			on_job_finished(current["name"], current["status"])
			repaired.append(f"{row}: {current['name']} was {current['status']}")
		except Exception:  # noqa: BLE001
			frappe.logger("server").error(f"could not reconcile migration {row}", exc_info=True)

	if repaired:
		frappe.db.commit()
	return {"repaired": repaired}
