# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One security finding.

Deliberately polymorphic. The detectors have nothing in common — a systemd unit
appearing, a key added to authorized_keys, an outbound connection to port 22 —
but what happens next is identical for all of them: deduplicate, route by
severity, let someone acknowledge it, and keep it.

Two rules are enforced here rather than left to callers:

  * **Deduplication is by subject and day.** The same condition seen on every
    scan is one alert with a count, not ninety-six. This is the same mechanism
    the SSH alerting already uses, and the reason it works is that the subject
    names the CONDITION and never a measurement — a percentage that drifts
    makes every reading a new alert.

  * **Suppression expires.** An operator can silence something for a stated
    window with a stated reason. There is no way to silence it permanently,
    because permanent suppression is how alerting quietly dies.
"""

import frappe
from frappe.model.document import Document

SEVERITIES = ("Critical", "High", "Medium", "Info")

#: Findings are the evidence of an intrusion. A year covers the eight-month
#: compromise that motivated this, with room either side.
DEFAULT_RETENTION_DAYS = 365


class SecurityEvent(Document):
	def before_insert(self):
		self.event_time = self.event_time or frappe.utils.now_datetime()
		self.last_seen = self.event_time
		self.host = self.host or frappe.utils.get_host_name_from_request() or _hostname()
		self.dedupe_key = self.dedupe_key or build_dedupe_key(self.subject, self.event_time)
		self.occurrences = self.occurrences or 1

	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("Security Event")
		frappe.db.delete(table, filters=(table.creation < (Now() - Interval(days=days))))


def _hostname() -> str:
	import os

	return os.uname().nodename


def build_dedupe_key(subject: str, when=None) -> str:
	"""Subject plus the day.

	The day is what turns "skip a duplicate" into "tell me once a day about
	this". Without it a standing condition alerts once and then never again,
	however long it persists; with a finer timestamp it alerts every scan.
	"""
	day = frappe.utils.getdate(when or frappe.utils.now_datetime())
	return f"{subject}|{day}"[:200]


def raise_event(
	severity: str,
	category: str,
	subject: str,
	detail: str,
	runbook: str = "",
	source_doctype: str = "",
	source_name: str = "",
) -> str | None:
	"""Record a finding, or count it against the one already standing.

	Returns the event name when something new was recorded, and None when it
	was folded into an existing one — which is what the caller needs to decide
	whether to notify.
	"""
	if severity not in SEVERITIES:
		severity = "Medium"

	now = frappe.utils.now_datetime()
	key = build_dedupe_key(subject, now)

	existing = frappe.db.get_value(
		"Security Event", {"dedupe_key": key}, ["name", "status", "suppressed_until"], as_dict=True
	)
	if existing:
		frappe.db.set_value(
			"Security Event",
			existing.name,
			{
				"occurrences": (frappe.db.get_value("Security Event", existing.name, "occurrences") or 1) + 1,
				"last_seen": now,
			},
			update_modified=False,
		)
		return None

	doc = frappe.get_doc(
		{
			"doctype": "Security Event",
			"event_time": now,
			"severity": severity,
			"category": category,
			"subject": subject[:200],
			"detail": detail,
			"runbook": runbook,
			"source_doctype": source_doctype,
			"source_name": source_name,
			"dedupe_key": key,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc.name


def is_suppressed(category: str, subject: str) -> bool:
	"""Is this condition currently silenced, and has the silence not expired?"""
	now = frappe.utils.now_datetime()
	return bool(
		frappe.db.exists(
			"Security Event",
			{
				"category": category,
				"subject": subject[:200],
				"status": "Suppressed",
				"suppressed_until": [">", now],
			},
		)
	)
