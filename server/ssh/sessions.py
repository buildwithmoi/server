# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Turning a stream of log lines into "who was here, and what did they do".

The events this app ingests answer questions one line at a time: somebody
authenticated, somebody ran a command, somebody disconnected. The question
anyone actually asks after an intrusion is a join — *this* login, from *that*
address, ran *these* commands — and no single line contains it.

TWO WAYS TO MAKE THE JOIN, AND THEY ARE NOT EQUALLY TRUE.

  The audit session id is exact. PAM stamps every process in a login session
  with the same id, so a sudo record carrying `audit_session=42` belongs to
  the login carrying `audit_session=42`. There is nothing to infer.

  Username and time is a guess. When the audit id is absent -- and it is
  absent on this box for every record, which is why this distinction is built
  in rather than bolted on later -- all that is left is "a sudo by patoo at
  14:03, and patoo had a session open from 13:55 to 14:20". That is usually
  right and is not the same kind of fact. If patoo had TWO sessions open at
  14:03, from two different addresses, it is not even usually right.

So attribution records HOW it was made, and refuses to choose when more than
one session fits. `Ambiguous` is a real answer here: the alternative is a
console that shows a command attributed to a specific address with the same
confidence whether it was measured or assumed, and the whole point of this
app is being able to trust what it says about an intrusion.

The same reasoning as the parser invariant it sits behind: a log line is not a
fact about the world.

Frappe-free, like `ssh/parser.py`. Sessions are built and attributed here;
`server/ssh/sessionize.py` is the part that reads and writes the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

#: Events that mean a session began. `Accepted` is sshd's own word for a
#: successful authentication; `Session Opened` is PAM's, and a login produces
#: both. Either alone is enough, because LogLevel and PAM configuration decide
#: which of them is actually written.
OPENING = frozenset({"Accepted", "Session Opened"})

#: Events that mean it ended. `Disconnected` is included because a session
#: closed by the client's network dropping never produces a PAM close.
CLOSING = frozenset({"Session Closed", "Disconnected"})

STATUS_OPEN = "Open"
STATUS_CLOSED = "Closed"
#: Opened, never closed, and too old to still be running. Deliberately not
#: "Closed": the difference between "we saw it end" and "we stopped hearing
#: about it" is exactly the kind of detail that matters afterwards.
STATUS_UNKNOWN = "Unknown"

#: How the sudo -> session link was made.
BY_AUDIT_SESSION = "Audit Session"
BY_USER_AND_TIME = "User and Time"
AMBIGUOUS = "Ambiguous"
UNATTRIBUTED = "Unattributed"

#: A session with no closing event after this long is Unknown rather than
#: Open. Long enough that a genuine day-long session is not misreported;
#: short enough that a list of "currently open" sessions stays meaningful.
STALE_AFTER = timedelta(hours=36)


@dataclass(frozen=True)
class Event:
	"""The fields of an SSH Auth Event that sessionising needs."""

	event_time: datetime
	event_type: str
	session_key: str
	username: str = ""
	source_ip: str = ""
	country: str = ""
	auth_method: str = ""
	key_fingerprint: str = ""
	audit_session: str = ""
	pid: int | None = None
	hostname: str = ""


@dataclass(frozen=True)
class Command:
	"""The fields of an SSH Sudo Command that attribution needs."""

	name: str
	event_time: datetime
	actor: str
	audit_session: str = ""
	hostname: str = ""


@dataclass
class Session:
	session_key: str
	username: str = ""
	source_ip: str = ""
	country: str = ""
	auth_method: str = ""
	key_fingerprint: str = ""
	audit_session: str = ""
	pid: int | None = None
	hostname: str = ""
	login_time: datetime | None = None
	#: When the session was OBSERVED to end. Stays empty for a session that
	#: was never seen closing, because inventing one would be a claim.
	logout_time: datetime | None = None
	#: The last event of any kind belonging to this session. Not the same
	#: thing: it is the last evidence the session existed, which is how far
	#: attribution can honestly reach when no close was ever seen.
	last_seen: datetime | None = None
	status: str = STATUS_OPEN
	event_count: int = 0

	@property
	def duration(self) -> int:
		"""Seconds, or 0 while it is still open."""
		if not self.login_time or not self.logout_time:
			return 0
		return max(0, int((self.logout_time - self.login_time).total_seconds()))

	def covers(self, when: datetime) -> bool:
		"""Was this session running at `when`?

		An OPEN session extends to now, which is what makes a command run
		during a still-live session attributable at all.

		AN UNKNOWN SESSION DOES NOT. This is the difference between a useful
		answer and a useless one, and it was found by running the thing: on
		real data 229 of 256 commands came back Ambiguous, because every
		session that was never seen closing was treated as still running and
		so absorbed every command any later. Once a session is old enough to
		be declared Unknown, the honest window is the last evidence it existed
		-- not the present moment, and not an invented logout time.
		"""
		if not self.login_time or when < self.login_time:
			return False
		end = self.logout_time
		if end is None and self.status == STATUS_UNKNOWN:
			end = self.last_seen
		if end is None:
			return True
		return when <= end

	def as_dict(self) -> dict:
		return {
			"session_key": self.session_key,
			"username": self.username,
			"source_ip": self.source_ip,
			"country": self.country,
			"auth_method": self.auth_method,
			"key_fingerprint": self.key_fingerprint,
			"audit_session": self.audit_session,
			"pid": self.pid,
			"hostname": self.hostname,
			"login_time": self.login_time,
			"logout_time": self.logout_time,
			"last_seen": self.last_seen,
			"status": self.status,
			"duration": self.duration,
			"event_count": self.event_count,
		}


@dataclass(frozen=True)
class Attribution:
	"""One sudo command, and which session it belongs to."""

	command: str
	session_key: str = ""
	method: str = UNATTRIBUTED
	#: How many sessions fitted. Above one, `session_key` is deliberately empty.
	candidates: int = 0


def build_sessions(events: list[Event]) -> list[Session]:
	"""Group auth events into sessions, one per sshd connection.

	The key is the sshd child's pid, scoped by boot id where journald provides
	one -- see `parser._session_key`. That is the correlation sshd itself uses,
	so this is a grouping rather than an inference.

	A session is created only by an opening event. Failed authentications carry
	a session key too, because sshd forked a child to handle them, but a
	connection nobody got in through is not a session anyone was in.
	"""
	by_key: dict[str, list[Event]] = {}
	for event in events:
		if not event.session_key:
			continue
		by_key.setdefault(event.session_key, []).append(event)

	sessions = []
	for key, group in by_key.items():
		group.sort(key=lambda e: e.event_time)
		opening = [e for e in group if e.event_type in OPENING]
		if not opening:
			continue

		first = opening[0]
		closing = [e for e in group if e.event_type in CLOSING]

		session = Session(
			session_key=key,
			login_time=first.event_time,
			last_seen=group[-1].event_time,
			event_count=len(group),
			status=STATUS_CLOSED if closing else STATUS_OPEN,
			logout_time=closing[-1].event_time if closing else None,
		)

		# Fill each attribute from the first event that actually carries it.
		# sshd splits the information across lines -- the address is on the
		# `Accepted` line and the PAM `Session Opened` line has the username
		# and nothing else -- so taking everything from one event loses half of
		# it, and taking the last non-empty value lets a later, less specific
		# line overwrite a good one.
		for attribute in (
			"username",
			"source_ip",
			"country",
			"auth_method",
			"key_fingerprint",
			"audit_session",
			"hostname",
		):
			for event in group:
				value = getattr(event, attribute)
				if value:
					setattr(session, attribute, value)
					break

		session.pid = next((e.pid for e in group if e.pid is not None), None)
		sessions.append(session)

	sessions.sort(key=lambda s: (s.login_time or datetime.min, s.session_key))
	return sessions


def close_stale(sessions: list[Session], now: datetime, stale_after: timedelta = STALE_AFTER) -> int:
	"""Mark long-open sessions Unknown. Returns how many changed.

	Not Closed. An sshd that was killed, a host that lost power and a log that
	stopped being ingested all look like this, and none of them is "the user
	logged out" -- which is what a list of Closed sessions would be claiming.
	"""
	changed = 0
	for session in sessions:
		if session.status != STATUS_OPEN or not session.login_time:
			continue
		if now - session.login_time > stale_after:
			session.status = STATUS_UNKNOWN
			changed += 1
	return changed


def attribute_commands(sessions: list[Session], commands: list[Command]) -> list[Attribution]:
	"""Decide which session each sudo command belongs to.

	Exact where the audit session id allows it, inferred from username and time
	where it does not, and explicitly ambiguous where more than one session
	fits -- which is not a rare corner. Two terminals open from a laptop and a
	phone is two sessions for one user at the same moment, and a command run
	then genuinely cannot be attributed to either from the logs alone.
	"""
	by_audit: dict[str, list[Session]] = {}
	for session in sessions:
		if session.audit_session:
			by_audit.setdefault(session.audit_session, []).append(session)

	attributions = []
	for command in commands:
		exact = by_audit.get(command.audit_session or "", [])
		if len(exact) == 1:
			attributions.append(
				Attribution(command.name, exact[0].session_key, BY_AUDIT_SESSION, 1)
			)
			continue

		candidates = [
			session
			for session in sessions
			if session.username
			and session.username == command.actor
			and session.covers(command.event_time)
		]

		if len(candidates) == 1:
			attributions.append(
				Attribution(command.name, candidates[0].session_key, BY_USER_AND_TIME, 1)
			)
		elif len(candidates) > 1:
			# Refusing to choose IS the answer. Naming one of several would
			# put an address next to a command with no evidence for it.
			attributions.append(Attribution(command.name, "", AMBIGUOUS, len(candidates)))
		else:
			# Ran outside any known session: cron, a system service, a console
			# login, or a session whose log was never ingested.
			attributions.append(Attribution(command.name, "", UNATTRIBUTED, 0))

	return attributions


def summarise(sessions: list[Session], attributions: list[Attribution]) -> dict:
	"""Counts worth reporting, including how sound the attribution was.

	The last three matter as much as the first three: a console that does not
	say how much of what it shows was inferred is one that gets believed too
	much.
	"""
	counts: dict = {
		"sessions": len(sessions),
		"open": sum(1 for s in sessions if s.status == STATUS_OPEN),
		"closed": sum(1 for s in sessions if s.status == STATUS_CLOSED),
		"unknown": sum(1 for s in sessions if s.status == STATUS_UNKNOWN),
	}
	for method in (BY_AUDIT_SESSION, BY_USER_AND_TIME, AMBIGUOUS, UNATTRIBUTED):
		counts[method.lower().replace(" ", "_")] = sum(1 for a in attributions if a.method == method)
	return counts
