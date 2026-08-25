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


#: Everything that is recorded before it is trusted.
BASELINE_DOCTYPES = ("Persistence Item", "System Account", "Authorized Key", "Listening Socket")


def accept_baseline() -> dict:
	"""Mark everything currently recorded as reviewed and expected."""
	accepted = {}
	for doctype in BASELINE_DOCTYPES:
		names = frappe.get_all(
			doctype, filters={"status": ["!=", "Gone"], "is_baseline": 0}, pluck="name"
		)
		for name in names:
			frappe.db.set_value(doctype, name, "is_baseline", 1, update_modified=False)
		accepted[doctype] = len(names)
	names = [n for count in accepted.values() for n in range(count)]

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
	frappe.logger("server").info(
		f"security baseline accepted: {accepted} by {frappe.session.user}"
	)
	return {"accepted": sum(accepted.values()), "by_doctype": accepted}


def run_persistence_scan() -> dict:
	"""Scheduled entry point. Never raises — a detector that can crash the
	scheduler takes every other detector down with it."""
	try:
		return scan()
	except Exception as exc:
		frappe.logger("server").error(f"persistence scan failed: {exc}", exc_info=True)
		return {"error": str(exc)}


# ----------------------------------------------------------------------
# Accounts and keys
# ----------------------------------------------------------------------

ACCOUNT_FIELDS = ("uid", "gid", "shell", "home", "home_exists", "groups", "password_status")


def _account_row(account) -> dict:
	return {
		"uid": account.uid,
		"gid": account.gid,
		"shell": account.shell,
		"home": account.home,
		"home_exists": 1 if account.home_exists else 0,
		"can_log_in": 1 if account.can_log_in else 0,
		"privileged": 1 if account.privileged else 0,
		"groups": ", ".join(account.groups),
		"password_status": account.password_status,
	}


def _key_usage(fingerprints: set[str]) -> dict[str, list[str]]:
	"""Which addresses each key fingerprint has actually logged in from.

	The SSH login tracking already records the fingerprint on every publickey
	authentication, so this join costs one query and turns "a new key exists"
	into "a new key exists and it has already been used, from here".
	"""
	if not fingerprints:
		return {}

	rows = frappe.get_all(
		"SSH Auth Event",
		filters={"key_fingerprint": ["in", list(fingerprints)], "outcome": "Success"},
		fields=["key_fingerprint", "source_ip"],
		limit_page_length=0,
	)
	usage: dict[str, list[str]] = {}
	for row in rows:
		if row.source_ip and row.source_ip not in usage.setdefault(row.key_fingerprint, []):
			usage[row.key_fingerprint].append(row.source_ip)
	return usage


def scan_accounts(record_only: bool = False) -> dict:
	"""Compare the account and key list against what was recorded.

	On a first scan everything is recorded without being reported as new — but
	the SHAPE rules still run, because an account that already looks wrong is
	worth saying so about immediately. That is the difference between "this
	changed" and "this should not exist", and only the first needs a baseline.
	"""
	from server.security import account_rules, accounts as collector

	snapshot = collector.collect()
	now = frappe.utils.now_datetime()
	findings: list = []

	stored = {
		row.username: row
		for row in frappe.get_all(
			"System Account",
			filters={"status": "Active"},
			fields=["name", "username", *ACCOUNT_FIELDS, "can_log_in", "privileged"],
			limit_page_length=0,
		)
	}
	first_run = not stored

	seen = set()
	for account in snapshot.accounts:
		seen.add(account.username)
		row = _account_row(account)
		previous = stored.get(account.username)

		if previous is None:
			frappe.get_doc(
				{
					"doctype": "System Account",
					"username": account.username,
					**row,
					"last_login": snapshot.last_login.get(account.username, ""),
					"first_seen": now,
					"last_seen": now,
					"status": "Active",
					"is_baseline": 0,
				}
			).insert(ignore_permissions=True)
			if first_run:
				# Nothing to diff against, but a wrong shape is wrong today.
				findings.extend(account_rules.shape_findings(account))
			else:
				findings.extend(account_rules.judge_account(account_rules.APPEARED, account))
				_record_account_change(account.username, "Appeared", "", "", "", now)
			continue

		changed = {
			field: (previous.get(field), row[field])
			for field in ACCOUNT_FIELDS
			if str(previous.get(field) or "") != str(row[field] or "")
		}
		frappe.db.set_value(
			"System Account",
			previous.name,
			{**row, "last_login": snapshot.last_login.get(account.username, ""), "last_seen": now},
			update_modified=False,
		)
		if changed:
			was = collector.Account(
				username=account.username,
				uid=int(previous.get("uid") or 0),
				gid=int(previous.get("gid") or 0),
				shell=previous.get("shell") or "",
				home=previous.get("home") or "",
				home_exists=bool(previous.get("home_exists")),
				groups=tuple((previous.get("groups") or "").split(", ")) if previous.get("groups") else (),
				password_status=previous.get("password_status") or collector.PASSWORD_UNKNOWN,
			)
			findings.extend(account_rules.judge_account(account_rules.MODIFIED, account, was))
			for field, (old, new) in changed.items():
				_record_account_change(account.username, "Modified", field, str(old or ""), str(new or ""), now)

	for username, previous in stored.items():
		if username in seen:
			continue
		frappe.db.set_value("System Account", previous.name, "status", "Gone", update_modified=False)
		gone = collector.Account(
			username=username,
			uid=int(previous.get("uid") or 0),
			gid=int(previous.get("gid") or 0),
			shell=previous.get("shell") or "",
			home=previous.get("home") or "",
			groups=tuple((previous.get("groups") or "").split(", ")) if previous.get("groups") else (),
		)
		findings.extend(account_rules.judge_account(account_rules.DISAPPEARED, gone))
		_record_account_change(username, "Disappeared", "", "", "", now)

	findings.extend(_scan_keys(snapshot, first_run, now))
	findings.extend(account_rules.judge_coverage(snapshot.surfaces))

	raised = []
	if not record_only:
		for finding in findings:
			name = raise_event(
				finding.severity,
				finding.category,
				finding.subject,
				finding.detail,
				finding.runbook,
				source_doctype="System Account",
			)
			if name:
				raised.append(name)
				_notify(name)

	frappe.db.commit()
	return {
		"accounts": len(snapshot.accounts),
		"keys": len(snapshot.keys),
		"findings": len(findings),
		"raised": raised,
		"first_run": first_run,
		"unreadable": [s.as_dict() for s in snapshot.blind_spots],
		"record_only": record_only,
	}


def _scan_keys(snapshot, first_run: bool, now) -> list:
	from server.security import account_rules

	stored = {
		(row.fingerprint, row.account): row
		for row in frappe.get_all(
			"Authorized Key",
			filters={"status": "Active"},
			fields=["name", "fingerprint", "account"],
			limit_page_length=0,
		)
	}
	usage = _key_usage({key.fingerprint for key in snapshot.keys})
	findings = []
	seen = set()

	for key in snapshot.keys:
		identity = (key.fingerprint, key.account)
		seen.add(identity)
		used_from = usage.get(key.fingerprint, [])
		if identity in stored:
			frappe.db.set_value(
				"Authorized Key",
				stored[identity].name,
				{"last_seen": now, "used_from": ", ".join(used_from)},
				update_modified=False,
			)
			continue

		frappe.get_doc(
			{
				"doctype": "Authorized Key",
				"fingerprint": key.fingerprint,
				"account": key.account,
				"key_type": key.key_type,
				"comment": key.comment,
				"options": key.options,
				"path": key.path,
				"status": "Active",
				"is_baseline": 0,
				"first_seen": now,
				"last_seen": now,
				"used_from": ", ".join(used_from),
			}
		).insert(ignore_permissions=True)
		if not first_run:
			findings.extend(account_rules.judge_key(account_rules.APPEARED, key, used_from))

	for identity, row in stored.items():
		if identity in seen:
			continue
		frappe.db.set_value("Authorized Key", row.name, "status", "Removed", update_modified=False)
		from server.security.accounts import Key

		findings.extend(
			account_rules.judge_key(
				account_rules.DISAPPEARED, Key(row.account, "", row.fingerprint, "")
			)
		)
	return findings


def _record_account_change(username: str, change_type: str, field: str, old: str, new: str, now) -> None:
	frappe.get_doc(
		{
			"doctype": "System Account Change",
			"event_time": now,
			"username": username,
			"change_type": change_type,
			"field_changed": field,
			"old_value": old,
			"new_value": new,
		}
	).insert(ignore_permissions=True)


def run_account_scan() -> dict:
	"""Scheduled entry point. Never raises."""
	try:
		return scan_accounts()
	except Exception as exc:
		frappe.logger("server").error(f"account scan failed: {exc}", exc_info=True)
		return {"error": str(exc)}


# ----------------------------------------------------------------------
# Network
# ----------------------------------------------------------------------

#: Where the consecutive-SYN-SENT count lives between scans. A beacon retries
#: constantly, so it accumulates in minutes; losing the count to a redis
#: restart costs one detection cycle and nothing more.
BEACON_KEY = "server:security:syn-sent"

#: Where the last firewall ruleset hash lives, to notice it changing.
FIREWALL_KEY = "server:security:firewall-hash"


def _git_host_addresses() -> tuple[str, ...]:
	"""Addresses this estate legitimately reaches over SSH.

	Resolved rather than configured, because a git host's addresses change and
	a stale allowlist would start reporting `bench get-app` as an intrusion.
	Resolution failing is not an error — the check simply becomes stricter.
	"""
	import socket as pysocket

	from server.security.network_rules import GIT_HOSTS

	found: set[str] = set()
	for host in GIT_HOSTS:
		try:
			for info in pysocket.getaddrinfo(host, 22, proto=pysocket.IPPROTO_TCP):
				found.add(info[4][0])
		except OSError:
			continue
	return tuple(found)


def scan_network(record_only: bool = False) -> dict:
	"""Compare listening ports and outbound traffic against what is expected."""
	from server.security import network, network_rules

	snapshot = network.collect()
	now = frappe.utils.now_datetime()
	findings: list = []

	findings.extend(_scan_listeners(snapshot, now))
	findings.extend(
		network_rules.judge_outbound(snapshot.sockets, git_host_addresses=_git_host_addresses())
	)
	findings.extend(network_rules.judge_beacons(_track_beacons(snapshot)))
	_record_outbound(snapshot, now)

	for process in snapshot.processes:
		findings.extend(network_rules.judge_process(process))

	previous_firewall = frappe.cache.get_value(FIREWALL_KEY) or ""
	findings.extend(network_rules.judge_firewall(previous_firewall, snapshot))
	if snapshot.firewall_hash:
		frappe.cache.set_value(FIREWALL_KEY, snapshot.firewall_hash)

	findings.extend(network_rules.judge_coverage(snapshot.surfaces))

	raised = []
	if not record_only:
		for finding in findings:
			name = raise_event(
				finding.severity,
				finding.category,
				finding.subject,
				finding.detail,
				finding.runbook,
				source_doctype="Listening Socket",
			)
			if name:
				raised.append(name)
				_notify(name)

	frappe.db.commit()
	return {
		"sockets": len(snapshot.sockets),
		"processes": len(snapshot.processes),
		"findings": len(findings),
		"raised": raised,
		"unreadable": [s.as_dict() for s in snapshot.blind_spots],
		"record_only": record_only,
	}


def _scan_listeners(snapshot, now) -> list:
	from server.security import network_rules

	listeners = {
		(s.protocol, s.local_port, s.local_address): s
		for s in snapshot.sockets
		if s.state == "LISTEN"
	}
	stored = {
		(row.protocol, row.port, row.local_address): row
		for row in frappe.get_all(
			"Listening Socket",
			filters={"status": "Active"},
			fields=["name", "protocol", "port", "local_address", "process_name", "binary"],
			limit_page_length=0,
		)
	}
	first_run = not stored
	findings = []

	for key, socket in listeners.items():
		if key in stored:
			frappe.db.set_value(
				"Listening Socket", stored[key].name, "last_seen", now, update_modified=False
			)
			continue

		frappe.get_doc(
			{
				"doctype": "Listening Socket",
				"protocol": socket.protocol,
				"port": socket.local_port,
				"local_address": socket.local_address,
				"listening_publicly": 1 if socket.listening_publicly else 0,
				"process_name": socket.process,
				"binary": socket.binary,
				"binary_verified": 1 if socket.binary_verified else 0,
				"pid": socket.pid,
				"status": "Active",
				"is_baseline": 0,
				"first_seen": now,
				"last_seen": now,
			}
		).insert(ignore_permissions=True)
		if not first_run:
			findings.extend(network_rules.judge_new_listener(socket))

	for key, row in stored.items():
		if key in listeners:
			continue
		frappe.db.set_value("Listening Socket", row.name, "status", "Gone", update_modified=False)
		findings.extend(
			network_rules.judge_listener_gone(
				_listener_from_row(row)
			)
		)
	return findings


def _listener_from_row(row):
	from server.security.network import Socket

	return Socket(
		protocol=row.protocol,
		state="LISTEN",
		local_address=row.local_address,
		local_port=row.port,
		process=row.get("process_name") or "",
		binary=row.get("binary") or "",
	)


def _track_beacons(snapshot) -> dict:
	"""Count consecutive scans that saw SYN-SENT to the same endpoint.

	Kept in the cache rather than the database: it is a counter that resets,
	not a record worth keeping, and the endpoints that matter reach the
	threshold within a quarter of an hour.
	"""
	from server.security.network import STATE_SYN_SENT

	pending = {
		(s.remote_address, s.remote_port)
		for s in snapshot.sockets
		if s.state == STATE_SYN_SENT and s.remote_is_external
	}
	previous = frappe.cache.get_value(BEACON_KEY) or {}
	counts = {}
	for endpoint in pending:
		key = f"{endpoint[0]}:{endpoint[1]}"
		counts[key] = int(previous.get(key, 0)) + 1

	frappe.cache.set_value(BEACON_KEY, counts, expires_in_sec=3600)
	return {tuple(key.rsplit(":", 1)[0:1]) + (int(key.rsplit(":", 1)[1]),): value for key, value in counts.items()}


def _record_outbound(snapshot, now) -> None:
	"""Aggregate outbound destinations into the current hour.

	Raw connections are far too many to keep, and "this address, this port,
	this often" is the question anyone actually asks.
	"""
	from server.security.network import STATE_SYN_SENT

	bucket = now.replace(minute=0, second=0, microsecond=0)
	for socket in snapshot.sockets:
		if not socket.remote_is_external or socket.state == "LISTEN":
			continue

		existing = frappe.db.get_value(
			"Outbound Connection Summary",
			{
				"hour_bucket": bucket,
				"remote_address": socket.remote_address,
				"remote_port": socket.remote_port,
			},
			["name", "connection_count"],
			as_dict=True,
		)
		if existing:
			frappe.db.set_value(
				"Outbound Connection Summary",
				existing.name,
				{
					"connection_count": (existing.connection_count or 0) + 1,
					"syn_sent": 1 if socket.state == STATE_SYN_SENT else 0,
				},
				update_modified=False,
			)
			continue

		frappe.get_doc(
			{
				"doctype": "Outbound Connection Summary",
				"hour_bucket": bucket,
				"remote_address": socket.remote_address,
				"remote_port": socket.remote_port,
				"process_name": socket.process,
				"binary": socket.binary,
				"connection_count": 1,
				"syn_sent": 1 if socket.state == STATE_SYN_SENT else 0,
			}
		).insert(ignore_permissions=True)


def run_network_scan() -> dict:
	"""Scheduled entry point. Never raises."""
	try:
		return scan_network()
	except Exception as exc:
		frappe.logger("server").error(f"network scan failed: {exc}", exc_info=True)
		return {"error": str(exc)}
