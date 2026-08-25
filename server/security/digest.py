# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One message a day that says what state this machine is in.

Immediate alerting handles Critical and High, and stops there for a good
reason: a mailbox that receives every Medium is a mailbox nobody opens, and the
Mediums are then worse than useless because they made the Criticals harder to
see. But findings that never leave the console are findings nobody reads
either -- this app's own dashboard is not somewhere anyone sits.

So the middle severities are batched. Once a day, in one message: what was
raised, what is still open, what is being deliberately ignored and for how
much longer, and whether the detectors themselves are still running.

TWO THINGS THIS FIXES THAT IMMEDIATE ALERTING CANNOT.

  An unacknowledged Critical goes quiet. Deduplication is by subject and day,
  which turns "tell me on every scan" into "tell me once a day" -- correct for
  noise, wrong for a Critical raised at 3am that nobody has touched by 6pm.
  `escalations()` finds those, and they lead the digest.

  A suppression everyone forgot is a blind spot with a friendly name.
  Silencing a finding is legitimate and necessary; silencing it permanently by
  accident is how a monitored system quietly stops being monitored. Every
  active suppression is listed with its expiry, every time.

Frappe-free where it can be: `compose()` takes plain data and returns the
message, so the wording and the grouping are testable without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Reported immediately, one alert per condition per day.
IMMEDIATE = ("Critical", "High")
#: Batched into the digest instead.
BATCHED = ("Medium", "Info")

SEVERITY_ORDER = ("Critical", "High", "Medium", "Info")

#: A Critical still untouched after this long is raised again, louder. Chosen
#: to be longer than a working day is short: something raised in the morning
#: escalates that evening, something raised overnight escalates by lunchtime.
ESCALATE_CRITICAL_AFTER_HOURS = 8
#: Highs get a day, because a High is "look today" by definition.
ESCALATE_HIGH_AFTER_HOURS = 24


@dataclass(frozen=True)
class Item:
	"""One finding, flattened to what a digest needs."""

	name: str
	severity: str
	category: str
	subject: str
	occurrences: int = 1
	age_hours: float = 0.0
	runbook: str = ""


@dataclass(frozen=True)
class Suppression:
	subject: str
	category: str
	expires_in_hours: float
	reason: str = ""


@dataclass(frozen=True)
class Detector:
	source: str
	status: str
	minutes_since_run: float | None = None
	overdue: bool = False


@dataclass(frozen=True)
class Digest:
	host: str = ""
	escalated: tuple[Item, ...] = ()
	new_items: tuple[Item, ...] = ()
	open_items: tuple[Item, ...] = ()
	suppressions: tuple[Suppression, ...] = ()
	detectors: tuple[Detector, ...] = ()
	counts: dict = field(default_factory=dict)

	@property
	def is_quiet(self) -> bool:
		"""Nothing raised, nothing open, nothing overdue, nothing suppressed."""
		return not (self.escalated or self.new_items or self.open_items or self.unhealthy)

	@property
	def unhealthy(self) -> tuple[Detector, ...]:
		return tuple(d for d in self.detectors if d.overdue or d.status == "Error")


def escalation_threshold(severity: str) -> float | None:
	"""How many hours before an untouched finding is raised again."""
	if severity == "Critical":
		return ESCALATE_CRITICAL_AFTER_HOURS
	if severity == "High":
		return ESCALATE_HIGH_AFTER_HOURS
	return None


def needs_escalation(item: Item) -> bool:
	"""Has this been ignored long enough to say so again?

	Only for findings that were reported immediately. Escalating a Medium
	nobody acknowledged would mean escalating almost everything, since
	acknowledging a Medium is not something anyone routinely does.
	"""
	threshold = escalation_threshold(item.severity)
	return threshold is not None and item.age_hours >= threshold


def _plural(count: int, noun: str) -> str:
	return f"{count} {noun}" + ("" if count == 1 else "s")


def subject_line(digest: Digest, date_text: str) -> str:
	"""What arrives in the notification list, which is often all that is read.

	Leads with the worst thing rather than with the host name: a list of forty
	identical "Security digest" subjects is a list nobody scans.
	"""
	if digest.escalated:
		return f"[Escalated] {_plural(len(digest.escalated), 'unacknowledged finding')} — {date_text}"
	if digest.unhealthy:
		return f"[Detectors] {_plural(len(digest.unhealthy), 'detector')} not reporting — {date_text}"

	counts = digest.counts or {}
	for severity in SEVERITY_ORDER:
		if counts.get(severity):
			return f"[{severity}] {_plural(counts[severity], 'new finding')} — {date_text}"
	return f"[Quiet] Nothing to report — {date_text}"


def compose(digest: Digest, date_text: str) -> tuple[str, str]:
	"""Render the digest. Returns (subject, html body).

	Ordered by what a person should act on, not by what is easiest to compute:
	things being ignored, then things that are new, then things still open,
	then the state of the machinery itself.
	"""
	from html import escape

	parts: list[str] = []
	host = escape(digest.host or "this host")

	if digest.escalated:
		parts.append(
			"<h3 style='color:#b91c1c;margin:0 0 6px'>Still unacknowledged</h3>"
			"<p style='margin:0 0 10px;color:#555'>Reported earlier and not acted on. "
			"These were raised once and deduplicated since, so this is the second time "
			"you are hearing about them, not the first.</p>"
		)
		parts.append(_table(digest.escalated, escape, show_age=True))

	if digest.unhealthy:
		rows = "".join(
			f"<li><b>{escape(d.source)}</b> — {escape(d.status)}"
			+ (f", last ran {d.minutes_since_run:.0f} minutes ago" if d.minutes_since_run else "")
			+ "</li>"
			for d in digest.unhealthy
		)
		parts.append(
			"<h3 style='margin:14px 0 6px'>Detectors not reporting</h3>"
			"<p style='margin:0 0 6px;color:#555'>A detector that has stopped looks exactly "
			"like a machine on which nothing is happening.</p>"
			f"<ul style='margin:0 0 10px'>{rows}</ul>"
		)

	if digest.new_items:
		parts.append(f"<h3 style='margin:14px 0 6px'>Raised in the last day</h3>{_table(digest.new_items, escape)}")

	if digest.open_items:
		parts.append(
			f"<h3 style='margin:14px 0 6px'>Still open from before</h3>{_table(digest.open_items, escape, show_age=True)}"
		)

	if digest.suppressions:
		rows = "".join(
			f"<li>{escape(s.subject)} <span style='color:#888'>({escape(s.category)})</span> — "
			+ (
				f"silent for another {s.expires_in_hours:.0f} hours"
				if s.expires_in_hours > 0
				else "expired, will report again"
			)
			+ (f". {escape(s.reason)}" if s.reason else "")
			+ "</li>"
			for s in digest.suppressions
		)
		parts.append(
			"<h3 style='margin:14px 0 6px'>Deliberately silenced</h3>"
			"<p style='margin:0 0 6px;color:#555'>Listed every day on purpose. A suppression "
			"nobody remembers is a blind spot with a friendly name.</p>"
			f"<ul style='margin:0 0 10px'>{rows}</ul>"
		)

	if digest.is_quiet:
		parts.append(
			"<p>Nothing was raised, nothing is open, and every detector reported on schedule.</p>"
			"<p style='color:#888'>This message is sent even when there is nothing to say, "
			"so that its absence means something.</p>"
		)

	body = (
		f"<div style='font-family:system-ui,sans-serif;font-size:14px;line-height:1.5'>"
		f"<p style='color:#666;margin:0 0 12px'>Security digest for <b>{host}</b>, {escape(date_text)}.</p>"
		+ "".join(parts)
		+ "</div>"
	)
	return subject_line(digest, date_text), body


def _table(items, escape, show_age: bool = False) -> str:
	colours = {"Critical": "#b91c1c", "High": "#c2410c", "Medium": "#a16207", "Info": "#6b7280"}
	rows = []
	for item in items:
		age = f"<td style='color:#888;padding:2px 8px'>{item.age_hours:.0f}h</td>" if show_age else ""
		seen = (
			f"<td style='color:#888;padding:2px 8px'>×{item.occurrences}</td>"
			if item.occurrences > 1
			else "<td></td>"
		)
		rows.append(
			f"<tr><td style='padding:2px 8px;color:{colours.get(item.severity, '#333')};white-space:nowrap'>"
			f"<b>{escape(item.severity)}</b></td>"
			f"<td style='padding:2px 8px'>{escape(item.subject)}</td>{seen}{age}</tr>"
		)
	return f"<table style='border-collapse:collapse;margin:0 0 10px'>{''.join(rows)}</table>"


# ----------------------------------------------------------------------
# Gathering it from the database
# ----------------------------------------------------------------------


def gather(window_hours: int = 24) -> Digest:
	"""Build the digest from the last day's Security Events and heartbeats."""
	import os

	import frappe

	from server.server.doctype.ingest_heartbeat.ingest_heartbeat import overdue

	now = frappe.utils.now_datetime()
	since = frappe.utils.add_to_date(now, hours=-window_hours)

	def _item(row) -> Item:
		return Item(
			name=row.name,
			severity=row.severity,
			category=row.category or "",
			subject=row.subject or "",
			occurrences=row.occurrences or 1,
			age_hours=max(0.0, frappe.utils.time_diff_in_hours(now, row.event_time)),
			runbook=row.runbook or "",
		)

	fields = ["name", "severity", "category", "subject", "occurrences", "event_time", "runbook"]

	recent = [
		_item(row)
		for row in frappe.get_all(
			"Security Event",
			filters={"event_time": [">=", since], "status": ["!=", "Suppressed"]},
			fields=fields,
			order_by="event_time desc",
			limit_page_length=200,
		)
	]

	still_open = [
		_item(row)
		for row in frappe.get_all(
			"Security Event",
			filters={"status": "New", "event_time": ["<", since]},
			fields=fields,
			order_by="severity asc, event_time asc",
			limit_page_length=200,
		)
	]

	# Escalation looks at everything unacknowledged, not only the old ones: a
	# Critical raised nine hours ago is inside the window and still ignored.
	unacknowledged = [
		_item(row)
		for row in frappe.get_all(
			"Security Event",
			filters={"status": "New", "severity": ["in", IMMEDIATE]},
			fields=fields,
			order_by="event_time asc",
			limit_page_length=200,
		)
	]
	escalated = [item for item in unacknowledged if needs_escalation(item)]
	escalated_names = {item.name for item in escalated}

	suppressions = [
		Suppression(
			subject=row.subject or "",
			category=row.category or "",
			expires_in_hours=(
				frappe.utils.time_diff_in_hours(row.suppressed_until, now) if row.suppressed_until else 0.0
			),
			reason=row.suppression_reason or "",
		)
		for row in frappe.get_all(
			"Security Event",
			filters={"status": "Suppressed"},
			fields=["subject", "category", "suppressed_until", "suppression_reason"],
			limit_page_length=100,
		)
	]

	late = {entry["source"] for entry in overdue()}
	detectors = [
		Detector(
			source=row.source,
			status=row.last_status or "",
			minutes_since_run=(
				frappe.utils.time_diff_in_seconds(now, row.last_run) / 60 if row.last_run else None
			),
			overdue=row.source in late,
		)
		for row in frappe.get_all(
			"Ingest Heartbeat", fields=["source", "last_status", "last_run"], limit_page_length=50
		)
	]

	counts: dict[str, int] = {}
	for item in recent:
		counts[item.severity] = counts.get(item.severity, 0) + 1

	return Digest(
		host=os.uname().nodename,
		escalated=tuple(escalated),
		new_items=tuple(item for item in recent if item.name not in escalated_names),
		open_items=tuple(item for item in still_open if item.name not in escalated_names),
		suppressions=tuple(suppressions),
		detectors=tuple(detectors),
		counts=counts,
	)


def send(window_hours: int = 24) -> dict:
	"""Compose and deliver the daily digest.

	Sent even when there is nothing to say, so that its absence means
	something. A monitoring system that only speaks when there is bad news is
	indistinguishable, on a quiet day, from one that has stopped.
	"""
	import frappe

	from server.alerts import _notify
	from server.server.doctype.server_settings.server_settings import get_settings

	settings = get_settings()
	if not settings.security_scans_on():
		return {"skipped": "security scans are switched off"}

	recipients = settings.get_alert_recipients()
	if not recipients:
		return {"skipped": "no alert recipients configured"}

	digest = gather(window_hours)
	date_text = frappe.utils.format_date(frappe.utils.nowdate(), "medium")
	subject, body = compose(digest, date_text)

	# `_notify` dedupes on subject, and the subject carries the date, so a
	# second call on the same day is a no-op rather than a second message.
	_notify(recipients, subject, body, "Security Event", digest.escalated[0].name if digest.escalated else "")

	return {
		"subject": subject,
		"escalated": len(digest.escalated),
		"new": len(digest.new_items),
		"open": len(digest.open_items),
		"suppressed": len(digest.suppressions),
		"unhealthy_detectors": len(digest.unhealthy),
		"recipients": len(recipients),
	}
