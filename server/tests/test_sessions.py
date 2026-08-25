# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Joining logins to the commands they ran.

The events this app ingests answer questions one line at a time. The question
anyone asks after an intrusion is a join — this login, from that address, ran
these commands — and no single line contains it.

The tests that matter here are the ones about how sound the join is. The audit
session id makes it exact; username-and-time makes it a good guess; two
sessions open for one user makes it nothing at all. A console that presents
all three with the same confidence is one that gets believed too much, so
`Ambiguous` is asserted as a real answer rather than a gap.

No site and no database — `sessions.py` has no frappe import, which is what
lets the whole join be tested against hand-built events.
"""

import unittest
from datetime import datetime, timedelta

from server.ssh import sessions as core

T0 = datetime(2026, 8, 25, 12, 0, 0)


def _event(minutes, event_type, key="boot123:4021", **kwargs):
	fields = {
		"username": "patoo",
		"source_ip": "203.0.113.24",
		"pid": 4021,
		"hostname": "hetzner-prod",
	}
	fields.update(kwargs)
	return core.Event(
		event_time=T0 + timedelta(minutes=minutes),
		event_type=event_type,
		session_key=key,
		**fields,
	)


def _command(minutes, actor="patoo", name=None, audit_session=""):
	return core.Command(
		name=name or f"cmd-{minutes}",
		event_time=T0 + timedelta(minutes=minutes),
		actor=actor,
		audit_session=audit_session,
	)


class TestBuildingSessions(unittest.TestCase):
	def test_a_login_and_a_logout_become_one_session(self):
		sessions = core.build_sessions(
			[_event(0, "Accepted"), _event(1, "Session Opened"), _event(30, "Session Closed")]
		)
		self.assertEqual(len(sessions), 1)
		self.assertEqual(sessions[0].status, core.STATUS_CLOSED)
		self.assertEqual(sessions[0].duration, 30 * 60)

	def test_a_failed_connection_is_not_a_session(self):
		"""sshd forks a child for a failed login too, so it has a session key.

		A connection nobody got in through is not a session anyone was in, and
		counting it as one would put a "session" next to every brute-force
		attempt on a public server.
		"""
		self.assertEqual(core.build_sessions([_event(0, "Failed"), _event(1, "Failed")]), [])

	def test_disconnected_closes_a_session_without_pam(self):
		"""A dropped connection never produces a PAM close.

		Treating only `Session Closed` as an ending would leave every session
		that ended badly looking like it was still running.
		"""
		sessions = core.build_sessions([_event(0, "Accepted"), _event(5, "Disconnected")])
		self.assertEqual(sessions[0].status, core.STATUS_CLOSED)

	def test_attributes_are_taken_from_whichever_event_carries_them(self):
		"""sshd splits the facts across lines.

		The address is on the `Accepted` line; PAM's `Session Opened` has the
		username and nothing else. Reading everything from one event loses
		half of it, and taking the last non-empty value lets a later, less
		specific line overwrite a good one.
		"""
		sessions = core.build_sessions(
			[
				_event(0, "Accepted", username="", auth_method="publickey", key_fingerprint="SHA256:abc"),
				_event(1, "Session Opened", source_ip="", auth_method="", key_fingerprint=""),
			]
		)
		session = sessions[0]
		self.assertEqual(session.username, "patoo")
		self.assertEqual(session.source_ip, "203.0.113.24")
		self.assertEqual(session.auth_method, "publickey")
		self.assertEqual(session.key_fingerprint, "SHA256:abc")

	def test_two_connections_are_two_sessions(self):
		sessions = core.build_sessions(
			[_event(0, "Accepted", key="boot123:1"), _event(0, "Accepted", key="boot123:2")]
		)
		self.assertEqual(len(sessions), 2)

	def test_events_with_no_session_key_are_skipped(self):
		self.assertEqual(core.build_sessions([_event(0, "Accepted", key="")]), [])


class TestStaleSessions(unittest.TestCase):
	def test_an_old_open_session_becomes_unknown_not_closed(self):
		"""A killed sshd, a lost power supply and a stalled ingest look alike.

		None of them is "the user logged out", which is what a Closed session
		would be claiming.
		"""
		sessions = core.build_sessions([_event(0, "Accepted")])
		core.close_stale(sessions, T0 + timedelta(days=3))
		self.assertEqual(sessions[0].status, core.STATUS_UNKNOWN)
		self.assertIsNone(sessions[0].logout_time, "a logout time must never be invented")

	def test_a_recent_open_session_stays_open(self):
		sessions = core.build_sessions([_event(0, "Accepted")])
		core.close_stale(sessions, T0 + timedelta(hours=1))
		self.assertEqual(sessions[0].status, core.STATUS_OPEN)

	def test_a_closed_session_is_left_alone(self):
		sessions = core.build_sessions([_event(0, "Accepted"), _event(1, "Session Closed")])
		core.close_stale(sessions, T0 + timedelta(days=3))
		self.assertEqual(sessions[0].status, core.STATUS_CLOSED)


class TestAttribution(unittest.TestCase):
	def test_the_audit_session_id_is_exact(self):
		sessions = core.build_sessions([_event(0, "Accepted", audit_session="42")])
		result = core.attribute_commands(sessions, [_command(5, audit_session="42")])
		self.assertEqual(result[0].method, core.BY_AUDIT_SESSION)
		self.assertEqual(result[0].session_key, "boot123:4021")

	def test_the_audit_id_wins_over_the_time_window(self):
		"""Exact evidence must not be downgraded by a plausible coincidence."""
		sessions = core.build_sessions(
			[
				_event(0, "Accepted", key="a", audit_session="42"),
				_event(0, "Accepted", key="b", audit_session="99"),
			]
		)
		result = core.attribute_commands(sessions, [_command(5, audit_session="99")])
		self.assertEqual((result[0].session_key, result[0].method), ("b", core.BY_AUDIT_SESSION))

	def test_username_and_time_is_used_when_there_is_no_audit_id(self):
		"""Which is every record on a host logging to auth.log rather than journald.

		That is the case on the machine this was written on, so it is the path
		that actually runs rather than a fallback nobody reaches.
		"""
		sessions = core.build_sessions([_event(0, "Accepted"), _event(60, "Session Closed")])
		result = core.attribute_commands(sessions, [_command(30)])
		self.assertEqual(result[0].method, core.BY_USER_AND_TIME)

	def test_two_overlapping_sessions_for_one_user_are_ambiguous(self):
		"""Two terminals, a laptop and a phone. Not a rare corner.

		Naming one of them would put an address next to a command with no
		evidence for it, which is worse than saying nothing.
		"""
		sessions = core.build_sessions(
			[
				_event(0, "Accepted", key="a", source_ip="203.0.113.24"),
				_event(0, "Accepted", key="b", source_ip="198.51.100.7"),
				_event(60, "Session Closed", key="a"),
				_event(60, "Session Closed", key="b"),
			]
		)
		result = core.attribute_commands(sessions, [_command(30)])
		self.assertEqual(result[0].method, core.AMBIGUOUS)
		self.assertEqual(result[0].session_key, "", "an ambiguous command must not name a session")
		self.assertEqual(result[0].candidates, 2)

	def test_sequential_sessions_for_one_user_are_not_ambiguous(self):
		"""The common case, and the one that makes the feature worth having.

		Same user, two logins, one after the other — each command belongs to
		exactly one of them.
		"""
		sessions = core.build_sessions(
			[
				_event(0, "Accepted", key="a"),
				_event(10, "Session Closed", key="a"),
				_event(20, "Accepted", key="b"),
				_event(30, "Session Closed", key="b"),
			]
		)
		result = core.attribute_commands(sessions, [_command(5), _command(25)])
		self.assertEqual([r.session_key for r in result], ["a", "b"])
		self.assertEqual({r.method for r in result}, {core.BY_USER_AND_TIME})

	def test_a_command_by_another_user_is_not_attributed(self):
		sessions = core.build_sessions([_event(0, "Accepted"), _event(60, "Session Closed")])
		result = core.attribute_commands(sessions, [_command(30, actor="deploy")])
		self.assertEqual(result[0].method, core.UNATTRIBUTED)

	def test_a_command_outside_every_session_is_not_attributed(self):
		"""cron, a system service, or a console login at the keyboard."""
		sessions = core.build_sessions([_event(0, "Accepted"), _event(10, "Session Closed")])
		result = core.attribute_commands(sessions, [_command(120)])
		self.assertEqual(result[0].method, core.UNATTRIBUTED)

	def test_an_open_session_still_absorbs_current_commands(self):
		sessions = core.build_sessions([_event(0, "Accepted")])
		result = core.attribute_commands(sessions, [_command(5)])
		self.assertEqual(result[0].method, core.BY_USER_AND_TIME)


class TestUnknownSessionsStopAbsorbingCommands(unittest.TestCase):
	"""The bug that made the whole feature useless, found by running it.

	On real data 229 of 256 commands came back Ambiguous. Every session that
	was never seen closing was treated as still running, so a login from a
	week ago competed for a command run this morning — and with several such
	sessions per user, nothing could ever be attributed.
	"""

	def _week_old_and_today(self):
		sessions = core.build_sessions(
			[
				# A week-old login that was never seen ending.
				_event(-10080, "Accepted", key="old"),
				# This morning's login, still open.
				_event(0, "Accepted", key="today"),
			]
		)
		core.close_stale(sessions, T0 + timedelta(minutes=5))
		return sessions

	def test_the_old_session_is_unknown(self):
		by_key = {s.session_key: s for s in self._week_old_and_today()}
		self.assertEqual(by_key["old"].status, core.STATUS_UNKNOWN)
		self.assertEqual(by_key["today"].status, core.STATUS_OPEN)

	def test_an_unknown_session_no_longer_covers_the_present(self):
		by_key = {s.session_key: s for s in self._week_old_and_today()}
		self.assertFalse(by_key["old"].covers(T0 + timedelta(minutes=5)))
		self.assertTrue(by_key["today"].covers(T0 + timedelta(minutes=5)))

	def test_so_the_command_is_attributed_rather_than_ambiguous(self):
		result = core.attribute_commands(self._week_old_and_today(), [_command(5)])
		self.assertEqual(result[0].method, core.BY_USER_AND_TIME)
		self.assertEqual(result[0].session_key, "today")

	def test_an_unknown_session_still_covers_its_own_lifetime(self):
		"""Bounded by the last evidence it existed, not erased entirely.

		Commands run while it was demonstrably alive are still its.
		"""
		sessions = core.build_sessions(
			[_event(-10080, "Accepted", key="old"), _event(-10070, "Other", key="old")]
		)
		core.close_stale(sessions, T0)
		self.assertTrue(sessions[0].covers(T0 - timedelta(minutes=10075)))
		self.assertFalse(sessions[0].covers(T0 - timedelta(minutes=10000)))


class TestSummary(unittest.TestCase):
	def test_reports_how_sound_the_attribution_was(self):
		"""Not just how many — a console that hides this gets over-trusted."""
		sessions = core.build_sessions([_event(0, "Accepted"), _event(60, "Session Closed")])
		result = core.attribute_commands(sessions, [_command(30), _command(999, actor="nobody")])
		summary = core.summarise(sessions, result)
		self.assertEqual(summary["sessions"], 1)
		self.assertEqual(summary["user_and_time"], 1)
		self.assertEqual(summary["unattributed"], 1)
