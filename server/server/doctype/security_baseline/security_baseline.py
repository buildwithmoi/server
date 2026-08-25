# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The recorded state of something watched for drift, as a hash.

WHY THIS IS NOT `frappe.cache`. Drift detection compares against what was
there last time, so the comparison basis is as important as the check. Keeping
it in redis means it is lost on a restart — and, worse, that anyone able to
restart redis erases the app's memory of what the firewall and the SSH
configuration used to be, silently and without touching anything this app
would report. The whole point of watching the egress rules is that their
removal must not be quiet.

In the database it is backed up, survives a reboot, and changing it leaves the
same trail as changing anything else.

ONLY HASHES. Never the content. An `sshd_config` names bastion hosts, internal
addresses and account names; a firewall ruleset names the internal network.
The spec this was built from is explicit that the app must not become the
single richest target on the estate, so what is stored answers "did this
change" and nothing else.
"""

import json

import frappe
from frappe.model.document import Document


class SecurityBaseline(Document):
	pass


def get(key: str) -> str:
	"""The last recorded hash for `key`, or "" if it has never been recorded."""
	return frappe.db.get_value("Security Baseline", key, "value_hash") or ""


def get_many(prefix: str) -> dict[str, str]:
	"""Every recorded hash whose key starts with `prefix`, keyed without it.

	Used for the SSH config files, where the set of files is itself the thing
	being watched — a file appearing or disappearing matters as much as one
	changing, and that question cannot be asked one key at a time.
	"""
	rows = frappe.get_all(
		"Security Baseline",
		filters={"baseline_key": ["like", f"{prefix}%"]},
		fields=["baseline_key", "value_hash"],
		limit_page_length=0,
	)
	return {row.baseline_key[len(prefix) :]: row.value_hash for row in rows}


def record(key: str, value_hash: str, detail: dict | None = None) -> None:
	"""Store or update a hash, without touching `modified` on a no-op."""
	now = frappe.utils.now_datetime()
	existing = frappe.db.exists("Security Baseline", key)
	if existing:
		frappe.db.set_value(
			"Security Baseline",
			key,
			{"value_hash": value_hash, "last_seen": now, "detail": json.dumps(detail or {})},
			update_modified=False,
		)
		return

	frappe.get_doc(
		{
			"doctype": "Security Baseline",
			"baseline_key": key,
			"value_hash": value_hash,
			"first_seen": now,
			"last_seen": now,
			"detail": json.dumps(detail or {}),
		}
	).insert(ignore_permissions=True)


def forget(keys: list[str]) -> None:
	"""Drop baselines for things that no longer exist.

	Called when a watched file is gone, so it is reported as removed exactly
	once rather than on every scan forever after.
	"""
	for key in keys:
		frappe.db.delete("Security Baseline", {"baseline_key": key})
