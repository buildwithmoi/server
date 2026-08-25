# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Running the persistence scan and turning its diff into findings.

The collector says what is there; `rules` says what is worth reporting; this
holds the previous state, compares, records the change, and raises the event.

THE BASELINE IS NOT ASSUMED CLEAN. On the first scan everything is recorded and
nothing is reported as new — otherwise the first run would raise four hundred
alerts and teach its reader to ignore them. But the recorded state is marked
UNACCEPTED, and a standing finding says so until someone reviews it. That
distinction matters here specifically: these servers are rebuilt from snapshots
of a host that was compromised for eight months, so a scanner that silently
treats whatever it finds first as normal would adopt the malware as the
baseline.
"""

from __future__ import annotations

import json

import frappe

from server.security import persistence, rules
from server.server.doctype.security_event.security_event import raise_event

CATEGORY = "persistence"

#: Raised once, and left standing until someone accepts what was recorded.
BASELINE_SUBJECT = "Persistence baseline has not been reviewed"


def _hostname() -> str:
	import os

	return os.uname().nodename


def _stored_items() -> dict[tuple[str, str], frappe._dict]:
	rows = frappe.get_all(
		"Persistence Item",
		filters={"status": "Active"},
		fields=["name", "kind", "identifier", "content_hash", "package", "is_baseline"],
		limit_page_length=0,
	)
	return {(row.kind, row.identifier): row for row in rows}


def scan(record_only: bool = False) -> dict:
	"""Compare the host against what was recorded, and report the difference.

	`record_only` runs the scan and stores the result without raising anything —
	the log-only mode the spec asks for, so a new detector can be watched for a
	week before it is allowed to page anyone.
	"""
	found, surfaces = persistence.collect()
	previous = _stored_items()
	first_run = not previous
	now = frappe.utils.now_datetime()

	seen: set[tuple[str, str]] = set()
	changes: list[tuple[str, persistence.Item, str]] = []

	for item in found:
		key = (item.kind, item.identifier)
		seen.add(key)
		stored = previous.get(key)

		if stored is None:
			_insert_item(item, now, accepted=first_run)
			if not first_run:
				changes.append((rules.APPEARED, item, ""))
		elif stored.content_hash != item.content_hash:
			frappe.db.set_value(
				"Persistence Item",
				stored.name,
				{
					"content_hash": item.content_hash,
					"package": item.package,
					"package_owned": 1 if item.package_owned else 0,
					"detail": json.dumps(item.detail),
					"last_seen": now,
				},
				update_modified=False,
			)
			changes.append((rules.MODIFIED, item, stored.content_hash))
		else:
			frappe.db.set_value(
				"Persistence Item", stored.name, "last_seen", now, update_modified=False
			)

	for key, stored in previous.items():
		if key in seen:
			continue
		frappe.db.set_value("Persistence Item", stored.name, "status", "Gone", update_modified=False)
		changes.append(
			(
				rules.DISAPPEARED,
				persistence.Item(kind=stored.kind, identifier=stored.identifier, content_hash=""),
				stored.content_hash,
			)
		)

	findings: list[rules.Finding] = []
	for change_type, item, previous_hash in changes:
		_record_change(change_type, item, previous_hash, now)
		findings.extend(rules.judge(change_type, item, previous_hash))

	findings.extend(rules.judge_coverage(surfaces))

	raised = []
	if not record_only:
		if first_run:
			raised.append(_raise_baseline_notice(len(found)))
		elif _baseline_unaccepted():
			# Still standing, so keep it visible rather than letting it age out.
			raised.append(_raise_baseline_notice(len(found)))
		for finding in findings:
			name = raise_event(
				finding.severity,
				finding.category,
				finding.subject,
				finding.detail,
				finding.runbook,
				source_doctype="Persistence Item",
			)
			if name:
				raised.append(name)
				_notify(name)

	frappe.db.commit()
	return {
		"items": len(found),
		"changes": len(changes),
		"findings": len(findings),
		"raised": [name for name in raised if name],
		"first_run": first_run,
		"unreadable": [s.as_dict() for s in surfaces if not s.readable and s.reason != "does not exist"],
		"record_only": record_only,
	}


def _notify(event_name: str) -> None:
	"""Send it on, without letting a mail failure lose the finding.

	The event is already recorded by the time this runs, so an SMTP problem
	costs the notification and not the evidence.
	"""
	try:
		from server import alerts

		alerts.notify_security_event(event_name)
	except Exception:
		frappe.logger("server").warning(f"could not notify for {event_name}", exc_info=True)


def _insert_item(item: persistence.Item, now, accepted: bool) -> None:
	frappe.get_doc(
		{
			"doctype": "Persistence Item",
			"kind": item.kind,
			"identifier": item.identifier,
			"path": item.path,
			"content_hash": item.content_hash,
			"package": item.package,
			"package_owned": 1 if item.package_owned else 0,
			"detail": json.dumps(item.detail),
			"status": "Active",
			# Recorded, but NOT accepted. The first scan of a host that may
			# already be compromised must not adopt its malware as normal.
			"is_baseline": 0,
			"first_seen": now,
			"last_seen": now,
		}
	).insert(ignore_permissions=True)


def _record_change(change_type: str, item: persistence.Item, previous_hash: str, now) -> None:
	frappe.get_doc(
		{
			"doctype": "Persistence Change",
			"event_time": now,
			"kind": item.kind,
			"identifier": item.identifier,
			"change_type": change_type,
			"old_hash": previous_hash,
			"new_hash": item.content_hash,
			"package": item.package,
			"detail": json.dumps(item.detail),
		}
	).insert(ignore_permissions=True)


def _baseline_unaccepted() -> bool:
	return bool(frappe.db.exists("Persistence Item", {"status": "Active", "is_baseline": 0}))


def _raise_baseline_notice(count: int) -> str | None:
	return raise_event(
		"High",
		CATEGORY,
		BASELINE_SUBJECT,
		f"{count} persistence items are recorded on {_hostname()} and none has been reviewed. "
		"Until they are, this scan can only report what CHANGES from here — it cannot tell you "
		"whether what is already there belongs.",
		"Read through the recorded units, timers and cron entries — particularly anything owned "
		"by no package — and confirm you put them there. Then accept the baseline. This matters "
		"more than it sounds: a server rebuilt from a snapshot of a compromised host would "
		"otherwise record that host's persistence as normal and never mention it again.",
		source_doctype="Persistence Item",
	)


def accept_baseline() -> dict:
	"""Mark everything currently recorded as reviewed and expected."""
	names = frappe.get_all(
		"Persistence Item", filters={"status": "Active", "is_baseline": 0}, pluck="name"
	)
	for name in names:
		frappe.db.set_value("Persistence Item", name, "is_baseline", 1, update_modified=False)

	for event in frappe.get_all(
		"Security Event", filters={"subject": BASELINE_SUBJECT, "status": "New"}, pluck="name"
	):
		frappe.db.set_value(
			"Security Event",
			event,
			{
				"status": "Resolved",
				"acknowledged_by": frappe.session.user,
				"acknowledged_at": frappe.utils.now_datetime(),
			},
			update_modified=False,
		)

	frappe.db.commit()
	frappe.logger("server").info(f"persistence baseline accepted: {len(names)} items by {frappe.session.user}")
	return {"accepted": len(names)}


def run_persistence_scan() -> dict:
	"""Scheduled entry point. Never raises — a detector that can crash the
	scheduler takes every other detector down with it."""
	try:
		return scan()
	except Exception as exc:
		frappe.logger("server").error(f"persistence scan failed: {exc}", exc_info=True)
		return {"error": str(exc)}
