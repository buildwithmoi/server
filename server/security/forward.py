# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Getting the evidence off this machine.

The uncomfortable, load-bearing point in the specification: an agent running on
a compromised host cannot be trusted to report that host's compromise. Every
detector in this app runs here. An attacker with root can stop the scheduler,
delete the findings, or edit them — and the eight-month compromise that
motivated all of this had root the entire time.

So the local database is a convenience and the off-box copy is the evidence.
Each finding is POSTed as JSON to an endpoint on another machine as soon as it
is raised, and the local record remembers whether that succeeded. What has not
been delivered is retried; what cannot be delivered is said out loud, because
forwarding that has quietly stopped is the same blindness one step removed.

Deliberately a plain HTTPS POST with a bearer token rather than anything
cleverer. It is what every hosted log service already accepts, and a collector
you write yourself is twenty lines. A protocol nobody can stand up in an
afternoon does not get stood up.

Uses urllib rather than requests: this app declares no third-party Python
dependencies, and `bench get-app` cannot fail for a missing package it never
asked for.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import frappe

from server.server.doctype.server_settings.server_settings import get_settings

#: A forward that hangs would hold a worker. Findings are small.
TIMEOUT = 15

#: How many undelivered findings one retry pass will attempt. Bounded so a long
#: outage does not turn the catch-up into a job that never finishes.
RETRY_BATCH = 200

#: Consecutive failures before the operator is told forwarding is broken.
#: Deliberately small: forwarding is the control that makes the rest
#: trustworthy, so it failing matters more than most things this app reports.
FAILURE_ALERT_AFTER = 3

FAILURE_KEY = "server:security:forward-failures"


def _payload(event) -> dict:
	"""What the collector receives.

	The runbook is included on purpose. Whoever reads this on the collector may
	not have access to the host any more — which is precisely the situation
	where the finding matters most — so the record has to explain itself
	without it.
	"""
	return {
		"host": event.host or "",
		"event_id": event.name,
		"time": str(event.event_time),
		"severity": event.severity,
		"category": event.category,
		"subject": event.subject,
		"detail": event.detail or "",
		"runbook": event.runbook or "",
		"occurrences": event.occurrences or 1,
		"source_doctype": event.source_doctype or "",
		"source_name": event.source_name or "",
	}


def send(event_name: str) -> bool:
	"""Deliver one finding. Returns whether it left the machine.

	Never raises. A collector that is down must not stop the detector that
	found something — the local record is still written either way.
	"""
	settings = get_settings()
	endpoint, token = settings.forwarding_target()
	if not endpoint:
		return False

	try:
		event = frappe.get_doc("Security Event", event_name)
	except frappe.DoesNotExistError:
		return False

	body = json.dumps(_payload(event)).encode()
	request = urllib.request.Request(  # noqa: S310 - the endpoint is operator-configured
		endpoint,
		data=body,
		method="POST",
		headers={
			"Content-Type": "application/json",
			"User-Agent": "frappe-server-security/1",
			**({"Authorization": f"Bearer {token}"} if token else {}),
		},
	)

	try:
		with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
			delivered = 200 <= response.status < 300
			error = "" if delivered else f"HTTP {response.status}"
	except urllib.error.HTTPError as exc:
		delivered, error = False, f"HTTP {exc.code}"
	except Exception as exc:  # noqa: BLE001 - DNS, TLS, timeouts, anything
		delivered, error = False, f"{type(exc).__name__}: {exc}"

	frappe.db.set_value(
		"Security Event",
		event_name,
		{
			"forwarded": 1 if delivered else 0,
			"forward_attempts": (event.forward_attempts or 0) + 1,
			"forward_error": "" if delivered else error[:500],
		},
		update_modified=False,
	)
	_record_outcome(delivered, error)
	return delivered


def _record_outcome(delivered: bool, error: str) -> None:
	"""Notice when forwarding itself has stopped working.

	Silently failing to forward is the same blindness as not forwarding at all,
	one step removed — and it is the failure mode nobody looks for, because the
	findings still appear locally exactly as before.
	"""
	if delivered:
		frappe.cache.delete_value(FAILURE_KEY)
		return

	failures = int(frappe.cache.get_value(FAILURE_KEY) or 0) + 1
	frappe.cache.set_value(FAILURE_KEY, failures, expires_in_sec=86400)
	if failures != FAILURE_ALERT_AFTER:
		return

	from server.server.doctype.security_event.security_event import raise_event

	raise_event(
		"High",
		"monitoring",
		"Security findings are not reaching the collector",
		f"{failures} consecutive forwarding failures. Last error: {error}",
		"Off-box forwarding is what makes the rest of this dependable — an agent on a compromised "
		"host cannot be trusted to report that host's compromise. While this is failing, the only "
		"copy of these findings is on the machine they are about. Check the collector is up and "
		"the token still matches.",
	)


def retry_pending() -> dict:
	"""Deliver findings that have not left the machine yet.

	Runs on a schedule so a collector outage costs delivery latency rather than
	the evidence itself.
	"""
	settings = get_settings()
	endpoint, _ = settings.forwarding_target()
	if not endpoint:
		return {"forwarded": 0, "reason": "no forwarding endpoint configured"}

	pending = frappe.get_all(
		"Security Event",
		filters={"forwarded": 0},
		fields=["name"],
		order_by="creation asc",
		limit=RETRY_BATCH,
	)
	delivered = sum(1 for row in pending if send(row.name))
	frappe.db.commit()
	return {"attempted": len(pending), "forwarded": delivered}


def forward_async(event_name: str) -> None:
	"""Queue a forward so a slow collector never delays a detector.

	`enqueue_after_commit` because the event must exist in the database before
	the worker tries to read it.
	"""
	endpoint, _ = get_settings().forwarding_target()
	if not endpoint:
		return
	frappe.enqueue(
		"server.security.forward.send",
		queue="short",
		event_name=event_name,
		enqueue_after_commit=True,
	)
