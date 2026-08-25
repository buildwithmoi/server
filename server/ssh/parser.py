# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Pure parsers for SSH/PAM/sudo authentication log records.

WHY THIS MODULE IMPORTS NOTHING FROM FRAPPE. The development machine is WSL2 and
has no `openssh-server` installed at all — there is not one real `sshd` line in
its journal or its auth.log. Every rule here is therefore validated against
checked-in fixtures rather than live traffic, and the fixtures have to be
runnable without a bench, a site or a database. Keeping this module dependency-
free (stdlib only) is what lets the whole rule table be exercised with nothing
but an interpreter, which is the only place the rules can be iterated on before
the code ever reaches the real server:

    cd apps/server && ../../env/bin/python -m unittest discover -s server/tests -t .

Use the BENCH python, not the system one. `pyproject.toml` targets py3.14 and
ruff's formatter rewrites `except (A, B):` into 3.14's unparenthesised form
(PEP 758), so a system python3.12 fails to even import this module.

The same consequence applies to anything added later: if you need `frappe`, the
code belongs in `ingest.py`, not here.

TWO TRANSPORTS, ONE RULE TABLE. Events arrive either as journald JSON records or
as raw auth.log lines. Both are normalised into `SyslogLine` and handed to the
same `parse_sshd_message` / `parse_sudo_message`, so the two ingest paths cannot
drift apart. `tests/test_journal_bridge.py` asserts exactly that.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Vocabulary — these strings are the Select options on the DocTypes.
# ---------------------------------------------------------------------------

EVENT_ACCEPTED = "Accepted"
EVENT_FAILED = "Failed"
EVENT_INVALID_USER = "Invalid User"
EVENT_SESSION_OPENED = "Session Opened"
EVENT_SESSION_CLOSED = "Session Closed"
EVENT_DISCONNECTED = "Disconnected"
EVENT_REFUSED = "Refused"
EVENT_PROTOCOL_ERROR = "Protocol Error"
EVENT_OTHER = "Other"

OUTCOME_SUCCESS = "Success"
OUTCOME_FAILURE = "Failure"
OUTCOME_INFO = "Info"

SUDO_EXECUTED = "Executed"
SUDO_DENIED = "Denied"
SUDO_AUTH_FAILURE = "Auth Failure"

#: Programs whose messages this module knows how to turn into SSH auth events.
SSHD_PROGRAMS = frozenset({"sshd", "sshd-session", "sshd-auth"})
SUDO_PROGRAMS = frozenset({"sudo"})


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyslogLine:
	"""One transport-neutral log record, before its message has been interpreted."""

	timestamp: datetime
	hostname: str
	program: str
	message: str
	pid: int | None = None
	#: journald `_BOOT_ID`. Absent for auth.log, which is why `session_key`
	#: falls back to a hostname+date composite there.
	boot_id: str | None = None
	#: journald `_AUDIT_SESSION` — the kernel's own login-session id, and the
	#: only reliable link between an SSH login and the sudo commands it ran.
	audit_session: str | None = None


@dataclass(frozen=True)
class AuthEvent:
	"""A parsed sshd/PAM authentication event."""

	event_time: datetime
	event_type: str
	outcome: str
	raw_message: str
	hostname: str = ""
	program: str = ""
	pid: int | None = None
	username: str | None = None
	invalid_user: bool = False
	auth_method: str | None = None
	source_ip: str | None = None
	source_port: int | None = None
	key_fingerprint: str | None = None
	session_key: str | None = None
	audit_session: str | None = None


@dataclass(frozen=True)
class SudoEvent:
	"""A parsed sudo invocation or sudo PAM event."""

	event_time: datetime
	status: str
	raw_message: str
	hostname: str = ""
	pid: int | None = None
	actor: str | None = None
	target_user: str | None = None
	tty: str | None = None
	pwd: str | None = None
	command: str | None = None
	failure_reason: str | None = None
	audit_session: str | None = None


# ---------------------------------------------------------------------------
# Syslog prefix
# ---------------------------------------------------------------------------

# Ubuntu 22.04+ rsyslog writes RFC3339 timestamps. Note the pid bracket is
# OPTIONAL: `sudo:` and `(systemd):` emit none, while `CRON[181265]:` does.
_RFC3339_PREFIX = re.compile(
	r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
	r"(?P<host>\S+)\s+"
	r"(?P<prog>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s?"
	r"(?P<msg>.*)$"
)

# Older distros (and anything still on classic syslog format) emit `Aug 23
# 00:00:36`. There is no year in the line at all — see `_infer_year`.
_CLASSIC_PREFIX = re.compile(
	r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
	r"(?P<host>\S+)\s+"
	r"(?P<prog>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s?"
	r"(?P<msg>.*)$"
)


def _infer_year(stamp: datetime, now: datetime) -> datetime:
	"""Attach a year to a classic-syslog timestamp that carries none.

	Rules, in order:
	1. Assume the current year.
	2. If that lands more than one day in the future, it is last year's log
	   being read just after New Year — roll back one year.

	Without rule 2, every December line read on 1 January is dated eleven
	months in the future and sorts to the top of the list view forever.
	"""
	candidate = stamp.replace(year=now.year)
	if candidate - now > timedelta(days=1):
		candidate = candidate.replace(year=now.year - 1)
	return candidate


def parse_syslog_line(line: str, now: datetime | None = None) -> SyslogLine | None:
	"""Split one raw log line into its syslog prefix and message body.

	Returns None for blank lines, logrotate banners and anything that does not
	carry a recognisable prefix — callers count those rather than failing, so a
	format we have not seen shows up as a number instead of an exception.
	"""
	line = line.rstrip("\n").rstrip("\r")
	if not line.strip():
		return None

	match = _RFC3339_PREFIX.match(line)
	if match:
		raw_ts = match.group("ts").replace("Z", "+00:00")
		try:
			stamp = datetime.fromisoformat(raw_ts)
		except ValueError:
			return None
	else:
		match = _CLASSIC_PREFIX.match(line)
		if not match:
			return None
		try:
			naive = datetime.strptime(match.group("ts"), "%b %d %H:%M:%S")
		except ValueError:
			return None
		stamp = _infer_year(naive, now or datetime.now())

	pid = match.group("pid")
	return SyslogLine(
		timestamp=stamp,
		hostname=match.group("host"),
		program=match.group("prog"),
		message=match.group("msg"),
		pid=int(pid) if pid else None,
	)


# ---------------------------------------------------------------------------
# Message normalisation
# ---------------------------------------------------------------------------

# OpenSSH prefixes some messages with `error: `, `fatal: ` or `error: PAM: `.
# Stripping it up front means each rule below matches one shape instead of four.
_LEADING_DECORATION = re.compile(r"^(?:(?:error|fatal): (?:PAM: )?)+")

# ...and suffixes them with any of ` port N`, ` on <addr>`, ` [preauth]`, in any
# order and up to three deep. Same reasoning, applied to the tail. This mirrors
# fail2ban's own `__suff` in /etc/fail2ban/filter.d/sshd.conf, which is the
# authoritative catalogue of what OpenSSH actually emits.
_TRAILING_DECORATION = re.compile(r"(?: (?:port \d+|on \S+|\[preauth\]))$")

_PORT = re.compile(r"\bport (?P<port>\d+)")


def _strip_decorations(message: str, max_suffixes: int = 3) -> str:
	"""Remove OpenSSH's optional severity prefix and trailing noise suffixes."""
	message = _LEADING_DECORATION.sub("", message).strip()
	for _ in range(max_suffixes):
		stripped = _TRAILING_DECORATION.sub("", message)
		if stripped == message:
			break
		message = stripped
	return message


_PREAUTH = re.compile(r"\[preauth\]")


def _is_preauth(message: str) -> bool:
	"""Did this event happen BEFORE the client authenticated?

	Checked against the original message, because `_strip_decorations` throws
	`[preauth]` away. It matters: without it a scanner that opens a socket and
	drops it is indistinguishable from a real user logging out cleanly, and both
	land in the charts as ordinary `Info` traffic.
	"""
	return bool(_PREAUTH.search(message))


def _extract_port(message: str) -> int | None:
	"""Pull the source port out of the ORIGINAL message.

	Deliberately run before `_strip_decorations`, which throws ` port N` away.
	The port is worth keeping: together with the IP it is what distinguishes two
	otherwise identical failed attempts in the same second.
	"""
	match = _PORT.search(message)
	return int(match.group("port")) if match else None


# ---------------------------------------------------------------------------
# sshd rules
# ---------------------------------------------------------------------------

# Ordered most-specific first. Every pattern is anchored at ^ but NOT at $, so
# residue that `_strip_decorations` left behind (` ssh2`, a stray ` port N` in
# the middle of a line) can never stop a rule matching.
#
# `auth_method` is captured as free text on purpose. OpenSSH emits at least
# `password`, `publickey`, `none`, `gssapi-with-mic` and `keyboard-interactive/pam`,
# and a build with extra auth modules can emit more. An enum here would silently
# drop exactly the unusual logins that are worth looking at.
_SSHD_RULES: list[tuple[re.Pattern[str], str, str]] = [
	(
		re.compile(
			r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
			r"(?:.*?:\s*(?P<fingerprint>\S+ \S+))?"
		),
		EVENT_ACCEPTED,
		OUTCOME_SUCCESS,
	),
	(
		re.compile(
			r"^Failed (?P<method>\S+) for (?:(?P<invalid>invalid user) )?(?P<user>\S+) from (?P<ip>\S+)"
		),
		EVENT_FAILED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^Invalid user\s*(?P<user>\S*) from (?P<ip>\S+)"),
		EVENT_INVALID_USER,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<user>[^(\s]+)"),
		EVENT_SESSION_OPENED,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)"),
		EVENT_SESSION_CLOSED,
		OUTCOME_INFO,
	),
	(
		re.compile(
			r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?"
		),
		EVENT_FAILED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^Connection closed by (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>\S+)"),
		EVENT_DISCONNECTED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^Disconnected from (?:(?P<invalid>invalid )?user (?P<user>\S+) )?(?P<ip>[\d.:a-fA-F]+)"),
		EVENT_DISCONNECTED,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^Received disconnect from (?P<ip>\S+)"),
		EVENT_DISCONNECTED,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^ROOT LOGIN REFUSED FROM (?P<ip>\S+)"),
		EVENT_REFUSED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(
			r"^maximum authentication attempts exceeded for "
			r"(?:(?P<invalid>invalid user) )?(?P<user>\S+) from (?P<ip>\S+)"
		),
		EVENT_FAILED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^User (?P<user>\S+) from (?P<ip>\S+) not allowed because"),
		EVENT_REFUSED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^Did not receive identification string from (?P<ip>\S+)"),
		EVENT_PROTOCOL_ERROR,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^Bad protocol version identification '.*?' from (?P<ip>\S+)"),
		EVENT_PROTOCOL_ERROR,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^kex_exchange_identification: (?:.*?(?:host|by) (?P<ip>[\d.]+|[0-9a-fA-F:]{3,}))?.*"),
		EVENT_PROTOCOL_ERROR,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^Timeout before authentication for (?P<ip>\S+)"),
		EVENT_PROTOCOL_ERROR,
		OUTCOME_INFO,
	),
	(
		re.compile(r"^Disconnecting (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>\S+)"),
		EVENT_FAILED,
		OUTCOME_FAILURE,
	),
	(
		re.compile(r"^Disconnecting:? Too many authentication failures(?: for (?P<user>\S+))?"),
		EVENT_FAILED,
		OUTCOME_FAILURE,
	),
	# LogLevel VERBOSE only. Last because it is the least specific.
	(
		re.compile(r"^Connection from (?P<ip>\S+)"),
		EVENT_OTHER,
		OUTCOME_INFO,
	),
]


#: sshd always appends the peer address as `from <ip> port <n>`, and the port
#: clause is what makes it unambiguous — a username cannot produce it, because
#: sshd writes the port itself.
_PEER_CLAUSE = re.compile(r"from\s+(?P<ip>[0-9A-Fa-f:.]+)\s+port\s+\d+")


def _authoritative_ip(message: str, matched: str | None) -> str | None:
	"""The address sshd actually saw, not the first one on the line.

	A username is echoed into the message before the peer address, so
	connecting as `b from 10.0.0.1` produces

	    Failed password for invalid user b from 10.0.0.1 from 203.0.113.9 port 55001

	and a rule that takes the first ` from ` records 10.0.0.1 — a real,
	well-formed, completely attacker-chosen address. That is worse than the
	`<script>` case: nothing rejects it, so it lands in the events, the
	"attacking IPs" chart and the geolocation cache, and the real source appears
	nowhere. An attacker can frame an arbitrary address while staying invisible.

	The peer clause is the trustworthy one because sshd writes the port itself,
	and the LAST such clause wins — anything a username injected comes earlier.
	"""
	peers = _PEER_CLAUSE.findall(message or "")
	for candidate in reversed(peers):
		cleaned = _clean_ip(candidate)
		if cleaned:
			return cleaned
	return _clean_ip(matched)


def _clean_ip(value: str | None) -> str | None:
	"""Return `value` only if it really is an IP address.

	The address is taken from a log line whose contents a remote client
	partially controls: sshd escapes control characters in a username but not
	spaces or angle brackets, so connecting as `a from <script>` makes
	`Invalid user a from <script> from 203.0.113.9 port 55000` — and the rule
	matches `<script>` as the address.

	That mattered well beyond a wrong value in a column. `source_ip` becomes the
	name of an IP Address Info document, frappe refuses `<` and `>` in a
	docname, and the resulting NameError aborted the whole ingest batch. The
	checkpoint was never advanced, so the same journal record was re-read and
	failed again every five minutes — SSH monitoring stopped permanently, and an
	unauthenticated attacker could switch it off at will. The raw line is still
	kept in `raw_message`, so nothing is lost by refusing to believe this field.
	"""
	text = (value or "").strip()
	if not text:
		return None
	try:
		ipaddress.ip_address(text)
	except ValueError:
		return None
	return text


def _session_key(line: SyslogLine) -> str | None:
	"""Build the key that ties one sshd process's events into a single session.

	sshd forks a child per connection, so its pid IS the correlation key and it
	is already in the syslog prefix. Rules, in order:
	1. No pid — no session (nothing to correlate on).
	2. journald: `<boot_id first 12>:<pid>`. Scoping by boot id is what stops
	   pid reuse across a reboot merging two unrelated logins.
	3. auth.log: `<hostname>:<pid>:<date>`, since no boot id is available. The
	   date is the cheapest available stand-in — pid reuse within one day on a
	   box with a 4-million pid space is not a practical concern.
	"""
	if line.pid is None:
		return None
	if line.boot_id:
		return f"{line.boot_id[:12]}:{line.pid}"
	return f"{line.hostname}:{line.pid}:{line.timestamp.date().isoformat()}"


def parse_sshd_message(line: SyslogLine) -> AuthEvent | None:
	"""Interpret one sshd/PAM message. Returns None if no rule matches."""
	port = _extract_port(line.message)
	preauth = _is_preauth(line.message)
	body = _strip_decorations(line.message)

	for pattern, event_type, outcome in _SSHD_RULES:
		match = pattern.search(body)
		if not match:
			continue
		groups = match.groupdict()
		user = groups.get("user") or None
		invalid = bool(groups.get("invalid")) or event_type == EVENT_INVALID_USER

		# A disconnect that happened pre-auth is an abandoned attempt, not a
		# session ending. Counting it as Failure is what puts scanner volume
		# into the attack charts instead of burying it in Info.
		if preauth and event_type == EVENT_DISCONNECTED and outcome == OUTCOME_INFO:
			outcome = OUTCOME_FAILURE
		return AuthEvent(
			event_time=line.timestamp,
			event_type=event_type,
			outcome=outcome,
			raw_message=line.message,
			hostname=line.hostname,
			program=line.program,
			pid=line.pid,
			username=user,
			invalid_user=invalid,
			auth_method=groups.get("method") or None,
			source_ip=_authoritative_ip(line.message, groups.get("ip")),
			source_port=port,
			key_fingerprint=groups.get("fingerprint") or None,
			session_key=_session_key(line),
			audit_session=line.audit_session,
		)
	return None


# ---------------------------------------------------------------------------
# sudo rules
# ---------------------------------------------------------------------------

# Real line from this box (note the leading whitespace after `sudo: `):
#     patoo : TTY=pts/2 ; PWD=/home/patoo ; USER=root ; COMMAND=/usr/bin/cat ...
# On a refusal, sudo replaces the TTY clause with free text:
#     patoo : a password is required ; PWD=... ; USER=root ; COMMAND=/usr/bin/true
_SUDO_COMMAND = re.compile(
	r"^\s*(?P<actor>\S+) : "
	r"(?:(?P<reason>[^;]*?) ; )??"
	r"(?:TTY=(?P<tty>\S+) ; )?"
	r"(?:PWD=(?P<pwd>\S+) ; )?"
	r"USER=(?P<target>\S+) ; "
	r"(?:TSID=\S+ ; )?"
	r"COMMAND=(?P<command>.*)$"
)

_SUDO_AUTH_FAILURE = re.compile(r"^pam_unix\(sudo:auth\): (?P<reason>.+)$")
_SUDO_NOT_IN_SUDOERS = re.compile(r"^\s*(?P<actor>\S+) : (?P<reason>user NOT in sudoers)\s*;")


#: Messages from a program we DO handle, which we deliberately choose not to
#: record. Distinct from "no rule matched": these are known and dismissed, and
#: conflating the two makes the unparsed counter permanently non-zero, which
#: trains everyone to ignore the one number that should mean "add a rule".
_KNOWN_NOISE = (
	re.compile(r"^pam_unix\(sudo:session\): session (?:opened|closed)"),
	re.compile(r"^pam_systemd\(sudo:session\)"),
)


def is_known_noise(line: SyslogLine) -> bool:
	"""Is this a message we have consciously decided not to turn into a row?"""
	return any(pattern.match(line.message.strip()) for pattern in _KNOWN_NOISE)


def parse_sudo_message(line: SyslogLine) -> SudoEvent | None:
	"""Interpret one sudo message. Returns None if no rule matches.

	`pam_unix(sudo:session)` open/close pairs are deliberately NOT parsed: they
	carry no actor, no command and no tty, so they would add two rows of pure
	noise for every one row that says something. The COMMAND record already
	carries everything worth keeping.
	"""
	message = line.message

	match = _SUDO_NOT_IN_SUDOERS.match(message)
	if match:
		return SudoEvent(
			event_time=line.timestamp,
			status=SUDO_DENIED,
			raw_message=message,
			hostname=line.hostname,
			pid=line.pid,
			actor=match.group("actor"),
			failure_reason=match.group("reason"),
			audit_session=line.audit_session,
		)

	match = _SUDO_COMMAND.match(message)
	if match:
		reason = (match.group("reason") or "").strip() or None
		return SudoEvent(
			event_time=line.timestamp,
			status=SUDO_DENIED if reason else SUDO_EXECUTED,
			raw_message=message,
			hostname=line.hostname,
			pid=line.pid,
			actor=match.group("actor"),
			target_user=match.group("target"),
			tty=match.group("tty"),
			pwd=match.group("pwd"),
			command=match.group("command"),
			failure_reason=reason,
			audit_session=line.audit_session,
		)

	match = _SUDO_AUTH_FAILURE.match(message)
	if match:
		return SudoEvent(
			event_time=line.timestamp,
			status=SUDO_AUTH_FAILURE,
			raw_message=message,
			hostname=line.hostname,
			pid=line.pid,
			failure_reason=match.group("reason"),
			audit_session=line.audit_session,
		)

	return None


# ---------------------------------------------------------------------------
# Transport entry points
# ---------------------------------------------------------------------------


def parse_syslog_record(line: SyslogLine) -> AuthEvent | SudoEvent | None:
	"""Dispatch a normalised record to the rule table for its program."""
	program = line.program
	if program in SSHD_PROGRAMS:
		return parse_sshd_message(line)
	if program in SUDO_PROGRAMS:
		return parse_sudo_message(line)
	return None


def parse_log_line(raw: str, now: datetime | None = None) -> AuthEvent | SudoEvent | None:
	"""Parse one raw auth.log line end to end."""
	line = parse_syslog_line(raw, now=now)
	return parse_syslog_record(line) if line else None


def journal_record_to_syslog_line(record: dict) -> SyslogLine | None:
	"""Normalise one `journalctl -o json` record into a `SyslogLine`.

	Field fallbacks matter here and are not defensive padding:
	- `SYSLOG_PID` is ABSENT on sudo's COMMAND records (verified on this box);
	  only `_PID` is set. Without the fallback every sudo row loses its pid and
	  with it its session correlation.
	- `SYSLOG_IDENTIFIER` is absent for anything logged over the native journal
	  protocol rather than syslog, where `_COMM` carries the program name.
	- `MESSAGE` is a list of byte values when the record contains non-UTF8 data.
	"""
	message = record.get("MESSAGE")
	if isinstance(message, list):
		message = bytes(message).decode("utf-8", errors="replace")
	if not isinstance(message, str):
		return None

	program = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or ""
	raw_pid = record.get("SYSLOG_PID") or record.get("_PID")
	try:
		pid = int(raw_pid) if raw_pid is not None else None
	except (TypeError, ValueError):
		pid = None

	try:
		micros = int(record["__REALTIME_TIMESTAMP"])
	except (KeyError, TypeError, ValueError):
		return None
	stamp = datetime.fromtimestamp(micros / 1_000_000, tz=UTC)

	return SyslogLine(
		timestamp=stamp,
		hostname=record.get("_HOSTNAME") or "",
		program=program,
		message=message,
		pid=pid,
		boot_id=record.get("_BOOT_ID"),
		audit_session=record.get("_AUDIT_SESSION"),
	)


def parse_journal_record(record: dict) -> AuthEvent | SudoEvent | None:
	"""Parse one `journalctl -o json` record end to end."""
	line = journal_record_to_syslog_line(record)
	return parse_syslog_record(line) if line else None


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def dedup_hash(timestamp: datetime, hostname: str, program: str, pid: int | None, message: str) -> str:
	"""Stable identity for one log record, used as a UNIQUE column.

	WHY SECOND RESOLUTION, NOT MICROSECOND. journald's `__REALTIME_TIMESTAMP` is
	the time the journal accepted the record; rsyslog's RFC3339 stamp in
	auth.log is the time rsyslog accepted it. They routinely disagree by tens of
	microseconds for the same event. Truncating to the second is what lets the
	journald and auth.log paths agree that they have seen the same thing — which
	is the whole point, because a cursor loss makes us re-read a window that may
	already have been ingested through the other source.

	The collision this trades away is two byte-identical messages from the same
	pid in the same second. For sshd that cannot happen (the source port is in
	the message); for sudo it would mean the same command logged twice in one
	second by one process, which is not a distinction worth keeping.
	"""
	epoch = int(timestamp.timestamp())
	payload = f"{epoch}|{hostname}|{program}|{pid if pid is not None else ''}|{message}"
	return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()


def event_dedup_hash(line: SyslogLine) -> str:
	"""Convenience wrapper: the dedup hash for an already-normalised record."""
	return dedup_hash(line.timestamp, line.hostname, line.program, line.pid, line.message)
