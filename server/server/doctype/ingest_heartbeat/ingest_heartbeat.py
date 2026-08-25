# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""When each detector last completed.

The point of this record is what it says when it STOPS being updated. Every
detector in this app runs on the host it is watching, so an attacker with root
can simply stop the scheduler — and a monitoring console that has quietly
stopped collecting looks exactly like a server on which nothing is happening.

The sequence is monotonic and never resets. A watcher outside this host can
then tell three different things apart: the number is climbing (running), the
number is unchanged (stopped), and the number went backwards (the database was
replaced with an older copy).
"""

import frappe
from frappe.model.document import Document

#: How late a detector may be before it is considered stopped, as a multiple of
#: its own schedule. Two missed runs rather than one: a single slow run on a
#: busy box is not an incident, and an alert that fires on it gets muted.
LATE_MULTIPLIER = 2.5


class IngestHeartbeat(Document):
	pass


def beat(source: str, expected_every: int, findings: int = 0, error: str = "") -> int:
	"""Record that `source` completed. Returns its new sequence number."""
	existing = frappe.db.get_value("Ingest Heartbeat", source, "sequence")
	sequence = (existing or 0) + 1

	values = {
		"last_run": frappe.utils.now_datetime(),
		"sequence": sequence,
		"expected_every": expected_every,
		"last_status": "Error" if error else "OK",
		"last_error": error[:500],
		"findings_last_run": findings,
	}
	if existing is None:
		doc = frappe.get_doc({"doctype": "Ingest Heartbeat", "source": source, **values})
		doc.insert(ignore_permissions=True)
	else:
		frappe.db.set_value("Ingest Heartbeat", source, values, update_modified=False)
	return sequence


def lateness(age_seconds: float, expected_every: int) -> int | None:
	"""How late a detector is, or None if it is still within tolerance.

	Pure so the tolerance itself can be tested without a database, because this
	one number decides whether a quiet detector reads as healthy. The multiplier
	buys a missed run before alerting: a scheduler that is briefly busy is the
	common case, and an alert on every single skipped tick is how a monitoring
	system teaches its operator to ignore it.

	Late is measured against the SCHEDULE, not against the tolerance -- "40
	minutes late" for a 5-minute detector is the useful sentence, and it stays
	true if the multiplier is ever retuned.
	"""
	if not expected_every or age_seconds <= expected_every * LATE_MULTIPLIER:
		return None
	return int(age_seconds - expected_every)


def overdue() -> list[dict]:
	"""Detectors that should have run by now and have not.

	Local self-checking catches a crashed scheduler, which is the common case.
	It cannot catch a hostile root — a process that has been stopped cannot
	notice that it has been stopped. That is what the external watchdog is for,
	and why this function is not the whole answer.
	"""
	now = frappe.utils.now_datetime()
	late = []
	for row in frappe.get_all(
		"Ingest Heartbeat",
		fields=["source", "last_run", "expected_every", "sequence", "last_status"],
	):
		if not row.last_run or not row.expected_every:
			continue
		age = frappe.utils.time_diff_in_seconds(now, row.last_run)
		seconds_late = lateness(age, row.expected_every)
		if seconds_late is not None:
			late.append(
				{
					"source": row.source,
					"seconds_late": seconds_late,
					"expected_every": row.expected_every,
					"last_run": str(row.last_run),
					"sequence": row.sequence,
				}
			)
	return late
