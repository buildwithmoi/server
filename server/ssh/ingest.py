# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The ingest orchestrator: read, parse, deduplicate, insert, checkpoint.

COMMIT ORDERING IS THE LOAD-BEARING DECISION HERE, and it is not arbitrary:

    insert rows -> commit -> write checkpoint -> commit

A crash between the two commits replays a window of records, and every row
carries a UNIQUE dedup hash, so the replay inserts nothing new. Doing it the
other way round — checkpoint first — would mean a crash silently loses every
record read in that run, permanently, with nothing to show it happened. Slow and
correct beats fast and lossy for an audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

import frappe
from frappe.utils import get_system_timezone

from server.server.doctype.ip_address_info.ip_address_info import ensure_ip
from server.server.doctype.server_ingest_checkpoint import server_ingest_checkpoint as checkpoint_module
from server.server.doctype.server_ingest_checkpoint.server_ingest_checkpoint import get_checkpoint
from server.server.doctype.server_settings.server_settings import get_settings
from server.ssh import authlog, journal, parser, sources

#: Deduplicating a slow run against itself. Without this a five-minute schedule
#: on a box with 1.6 GB free could stack a dozen workers all reading the same
#: backlog.
INGEST_JOB_ID = "server::ssh_ingest"


def to_site_datetime(stamp: datetime) -> datetime:
	"""Convert a parsed timestamp into what MariaDB and frappe expect.

	THE BUG THIS FIXES. The parser yields timezone-AWARE datetimes — journald
	records are UTC, and Ubuntu's RFC3339 auth.log carries an explicit offset.
	MariaDB DATETIME columns reject a value with an offset outright
	("Incorrect datetime value"), so the row never inserts. Frappe stores naive
	datetimes in the site's own timezone, so that is what we must hand it.

	The naive case is not a fallback for bad data: classic BSD-syslog lines
	genuinely carry no offset, and rsyslog writes them in the MACHINE's local
	time. Stamping them with the machine's zone before converting is what keeps
	the two log formats agreeing about when something happened.

	Note this makes the SITE timezone load-bearing for how event times read. If
	the site is left on frappe's Asia/Kolkata default while the server logs in
	UTC, every event displays hours away from when it happened — which is why
	`check_log_source()` reports both zones.
	"""
	if stamp.tzinfo is None:
		stamp = stamp.replace(tzinfo=datetime.now().astimezone().tzinfo)
	return stamp.astimezone(ZoneInfo(get_system_timezone())).replace(tzinfo=None)


@dataclass
class IngestStats:
	read: int = 0
	inserted: int = 0
	skipped: int = 0
	unparsed: int = 0
	ignored: int = 0
	unparsed_samples: list[str] = field(default_factory=list)

	def as_dict(self) -> dict:
		return {
			"read": self.read,
			"inserted": self.inserted,
			"skipped": self.skipped,
			"unparsed": self.unparsed,
			"ignored": self.ignored,
		}


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------


def _auth_event_doc(event: parser.AuthEvent, dedup: str, ingest_source: str, ip_name: str | None) -> dict:
	return {
		"doctype": "SSH Auth Event",
		"event_time": to_site_datetime(event.event_time),
		"event_type": event.event_type,
		"outcome": event.outcome,
		"username": event.username,
		"invalid_user": 1 if event.invalid_user else 0,
		"auth_method": event.auth_method,
		"source_ip": ip_name,
		"source_port": event.source_port,
		"key_fingerprint": event.key_fingerprint,
		"session_key": event.session_key,
		"audit_session": event.audit_session,
		"hostname": event.hostname,
		"program": event.program,
		"pid": event.pid,
		"ingest_source": ingest_source,
		"raw_message": event.raw_message,
		"dedup_hash": dedup,
	}


def _sudo_command_doc(event: parser.SudoEvent, dedup: str, ingest_source: str) -> dict:
	return {
		"doctype": "SSH Sudo Command",
		"event_time": to_site_datetime(event.event_time),
		"actor": event.actor,
		"target_user": event.target_user,
		"tty": event.tty,
		"pwd": event.pwd,
		"command": event.command,
		"status": event.status,
		"failure_reason": event.failure_reason,
		"audit_session": event.audit_session,
		"hostname": event.hostname,
		"pid": event.pid,
		"ingest_source": ingest_source,
		"raw_message": event.raw_message,
		"dedup_hash": dedup,
	}


def _insert(doc: dict, stats: IngestStats) -> None:
	"""Insert one row, treating a duplicate as success rather than an error.

	The UNIQUE index on `dedup_hash` is what makes re-reading a window safe, and
	catching the duplicate here is how that safety is actually collected. Each
	insert gets its own savepoint so one duplicate cannot roll back the batch.

	BOTH exceptions are caught, and they are NOT related by inheritance:
	frappe raises `UniqueValidationError` (a ValidationError) when a unique
	COLUMN collides, and `DuplicateEntryError` (a NameError) when the document
	NAME collides. Our dedup hash is a unique column, so the first is the one
	that actually fires — catching only the second, which is the more commonly
	cited of the two, makes every re-read blow up instead of being absorbed.
	"""
	savepoint = f"ingest_{stats.read}"
	try:
		frappe.db.savepoint(savepoint)
		frappe.get_doc(doc).insert(ignore_permissions=True)
		stats.inserted += 1
	except frappe.UniqueValidationError, frappe.DuplicateEntryError:
		frappe.db.rollback(save_point=savepoint)
		stats.skipped += 1


# ---------------------------------------------------------------------------
# The shared pipeline
# ---------------------------------------------------------------------------


def ingest_syslog_lines(lines: list[parser.SyslogLine], ingest_source: str) -> IngestStats:
	"""Turn normalised records into rows. Shared by every transport.

	Keeping journald, auth.log and fixture replay on one code path is what makes
	`replay_fixture` a genuine rehearsal rather than a separate toy
	implementation that can drift from the real thing.
	"""
	settings = get_settings()
	ignored_programs = settings.get_ignored_programs()
	stats = IngestStats()
	seen_ips: dict[str, str | None] = {}

	for line in lines:
		stats.read += 1

		if line.program in ignored_programs:
			stats.ignored += 1
			continue

		event = parser.parse_syslog_record(line)
		if event is None:
			# Only count it as unparsed if it was a program we claim to handle
			# AND the message is not something we knowingly drop. An unmatched
			# `polkitd` line is not a gap in our rules, and neither is sudo's
			# session open/close pair, which carries no actor and no command.
			if line.program in parser.SSHD_PROGRAMS | parser.SUDO_PROGRAMS and not parser.is_known_noise(
				line
			):
				stats.unparsed += 1
				if len(stats.unparsed_samples) < 5:
					stats.unparsed_samples.append(f"{line.program}: {line.message}"[:200])
			continue

		dedup = parser.event_dedup_hash(line)

		if isinstance(event, parser.AuthEvent):
			ip_name = None
			if event.source_ip:
				if event.source_ip not in seen_ips:
					seen_ips[event.source_ip] = ensure_ip(
						event.source_ip, seen_at=to_site_datetime(event.event_time)
					)
				ip_name = seen_ips[event.source_ip]
			_insert(_auth_event_doc(event, dedup, ingest_source, ip_name), stats)
		else:
			_insert(_sudo_command_doc(event, dedup, ingest_source), stats)

	return stats


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


def _run_journald(cp, settings) -> tuple[IngestStats, str]:
	limit = int(settings.max_records_per_run or 5000)
	bootstrap = int(settings.bootstrap_hours or 24)

	try:
		records, last_cursor = journal.read_batch(
			cursor=cp.cursor or None, since_hours=bootstrap, limit=limit
		)
	except journal.CursorLostError:
		# The journal rotated past where we were. Bootstrap again and let the
		# dedup hash absorb whatever overlap that creates.
		cp.reset_position()
		records, last_cursor = journal.read_batch(cursor=None, since_hours=bootstrap, limit=limit)
		stats = _commit_records(
			[parser.journal_record_to_syslog_line(r) for r in records],
			checkpoint_module.SOURCE_JOURNALD,
		)
		cp.cursor = last_cursor
		return stats, checkpoint_module.STATUS_CURSOR_LOST

	stats = _commit_records(
		[parser.journal_record_to_syslog_line(r) for r in records],
		checkpoint_module.SOURCE_JOURNALD,
	)
	cp.cursor = last_cursor
	status = checkpoint_module.STATUS_OK if records else checkpoint_module.STATUS_NO_NEW
	return stats, status


def _run_authlog(cp, settings) -> tuple[IngestStats, str]:
	limit = int(settings.max_records_per_run or 5000)
	path = (settings.auth_log_path or "/var/log/auth.log").strip()

	raw_lines, inode, offset, signature = authlog.read_lines(
		path,
		inode=cp.inode or None,
		offset=int(cp.byte_offset or 0),
		limit=limit,
		signature=cp.file_signature or None,
	)
	stats = _commit_records(
		[parser.parse_syslog_line(raw) for raw in raw_lines],
		checkpoint_module.SOURCE_AUTHLOG,
	)
	cp.file_path = path
	cp.inode = inode
	cp.byte_offset = offset
	cp.file_signature = signature
	status = checkpoint_module.STATUS_OK if raw_lines else checkpoint_module.STATUS_NO_NEW
	return stats, status


def _commit_records(lines: list[parser.SyslogLine | None], ingest_source: str) -> IngestStats:
	"""Ingest, then COMMIT — before the caller writes the checkpoint.

	See the module docstring: the rows must be durable before the position that
	says "we already have those rows" is.
	"""
	stats = ingest_syslog_lines([line for line in lines if line is not None], ingest_source)
	frappe.db.commit()
	return stats


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run_ingest(source: str | None = None) -> dict:
	"""Read one batch from the active source and record the outcome.

	Returns a stats dict. Never raises out to the scheduler: an ingest failure
	must be visible on the checkpoint record, not just in the error log where
	nobody looks.
	"""
	settings = get_settings()
	detected, explanation = detect(source)

	if detected == sources.SOURCE_DISABLED:
		return {"source": detected, "reason": explanation, **IngestStats().as_dict()}

	sources.record_detected_source(detected)

	if detected == sources.SOURCE_NONE:
		cp = get_checkpoint(checkpoint_module.SOURCE_JOURNALD)
		cp.record_run(checkpoint_module.STATUS_UNAVAILABLE, error=explanation)
		frappe.db.commit()
		return {"source": detected, "reason": explanation, **IngestStats().as_dict()}

	cp = get_checkpoint(detected)
	try:
		if detected == checkpoint_module.SOURCE_JOURNALD:
			stats, status = _run_journald(cp, settings)
		else:
			stats, status = _run_authlog(cp, settings)
	except Exception as exc:
		frappe.db.rollback()
		frappe.logger("server").error(f"SSH ingest failed: {exc}", exc_info=True)
		cp = get_checkpoint(detected)
		cp.record_run(checkpoint_module.STATUS_ERROR, error=f"{type(exc).__name__}: {exc}")
		frappe.db.commit()
		return {"source": detected, "error": str(exc), **IngestStats().as_dict()}

	error = "; ".join(stats.unparsed_samples) if stats.unparsed_samples else None
	cp.record_run(
		status,
		read=stats.read,
		inserted=stats.inserted,
		skipped=stats.skipped,
		unparsed=stats.unparsed,
		error=error,
	)
	frappe.db.commit()

	if stats.unparsed:
		frappe.logger("server").warning(
			f"{stats.unparsed} sshd/sudo record(s) matched no parser rule. Samples: {error}"
		)

	return {"source": detected, "status": status, **stats.as_dict()}


def detect(source: str | None = None) -> tuple[str, str]:
	"""Resolve the source to use, honouring an explicit override."""
	if source:
		return source, f"explicitly requested: {source}"
	return sources.detect_source()


def enqueue_ingest() -> None:
	"""Scheduler entry point. Queues one ingest run on the long queue.

	`deduplicate=True` with a fixed job id is what guarantees that a run taking
	longer than the five-minute schedule cannot pile up behind itself.
	"""
	if get_settings().get_log_source() == sources.SOURCE_DISABLED:
		return

	frappe.enqueue(
		"server.ssh.ingest.run_ingest",
		queue="long",
		timeout=1500,
		job_id=INGEST_JOB_ID,
		deduplicate=True,
	)
