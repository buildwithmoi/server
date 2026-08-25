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
	sequence, chain_hash = _next_link(doc)
	doc.sequence = sequence
	doc.chain_hash = chain_hash
	doc.insert(ignore_permissions=True)
	return doc.name


# ----------------------------------------------------------------------
# Tamper evidence
# ----------------------------------------------------------------------


def content_digest(
	sequence: int, event_time, severity: str, category: str, subject: str, detail: str
) -> str:
	"""The part of a finding the chain commits to.

	Deliberately not every field. `status`, `occurrences`, `last_seen` and the
	forwarding columns all change legitimately after the row is written --
	acknowledging a finding must not look like tampering with one. What is
	covered is what the finding SAYS: when, how bad, about what.
	"""
	import hashlib

	canonical = "\x1f".join(
		[str(sequence), str(event_time), severity or "", category or "", subject or "", detail or ""]
	)
	return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def link_hash(previous_hash: str, digest: str) -> str:
	"""Chain one link to the last."""
	import hashlib

	return hashlib.sha256(f"{previous_hash}:{digest}".encode()).hexdigest()


def head() -> tuple[int, str]:
	"""(sequence, chain hash) of the most recent finding, or (0, "")."""
	row = frappe.db.sql(
		"""SELECT sequence, chain_hash FROM `tabSecurity Event`
		   ORDER BY sequence DESC LIMIT 1""",
		as_dict=True,
	)
	if not row or not row[0].sequence:
		return 0, ""
	return int(row[0].sequence), row[0].chain_hash or ""


def _next_link(doc) -> tuple[int, str]:
	previous_sequence, previous_hash = head()
	sequence = previous_sequence + 1
	digest = content_digest(
		sequence, doc.event_time, doc.severity, doc.category, doc.subject, doc.detail
	)
	return sequence, link_hash(previous_hash, digest)


def verify_chain(limit: int = 5000) -> dict:
	"""Walk the chain and report where it stops adding up.

	WHAT THIS DOES AND DOES NOT PROVE. It does not prove nobody tampered with
	the findings: an attacker with database access can delete a row and
	recompute every hash after it, and this check would then pass. What it
	proves is that nobody tampered with them CARELESSLY -- a plain `DELETE` or
	an `UPDATE` through the desk breaks every link that follows and is caught
	on the next run.

	Making it actually strong needs an anchor outside this database, which is
	what the other two halves of this phase are for: every finding is forwarded
	off the box as it is written, and the chain head is published in the signed
	heartbeat. A rewritten chain is then a chain that disagrees with the copies
	somebody else already has.
	"""
	rows = frappe.db.sql(
		"""SELECT name, sequence, chain_hash, event_time, severity, category, subject, detail
		   FROM `tabSecurity Event`
		   WHERE sequence IS NOT NULL AND sequence > 0
		   ORDER BY sequence ASC LIMIT %(limit)s""",
		{"limit": limit},
		as_dict=True,
	)
	if not rows:
		return {"checked": 0, "broken": [], "gaps": [], "ok": True}

	broken: list[dict] = []
	gaps: list[dict] = []
	previous_hash = ""
	expected = rows[0].sequence

	for row in rows:
		if row.sequence != expected:
			gaps.append({"expected": expected, "found": row.sequence, "name": row.name})
			expected = row.sequence
		expected += 1

		digest = content_digest(
			row.sequence, row.event_time, row.severity, row.category, row.subject, row.detail
		)
		if link_hash(previous_hash, digest) != (row.chain_hash or ""):
			broken.append(
				{"name": row.name, "sequence": row.sequence, "subject": (row.subject or "")[:80]}
			)
		previous_hash = row.chain_hash or ""

	return {"checked": len(rows), "broken": broken, "gaps": gaps, "ok": not broken and not gaps}


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
