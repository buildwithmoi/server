# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Cross-transport equivalence.

Events reach this app either as journald JSON or as auth.log text. Both paths
must agree, because a lost journal cursor makes the ingester re-read a window
that may already have been taken in through the other source. If the two paths
disagreed about what an event IS, dedup could not recognise the overlap and the
same login would appear twice.
"""

from __future__ import annotations

import unittest
from datetime import UTC, timezone
from typing import ClassVar

from server.ssh import parser
from server.ssh.parser import (
	AuthEvent,
	SudoEvent,
	journal_record_to_syslog_line,
	parse_journal_record,
	parse_log_line,
)
from server.tests._support import read_journal


class TestJournalFieldMapping(unittest.TestCase):
	def setUp(self):
		self.records = read_journal()

	def test_fixture_contains_real_and_synthetic_records(self):
		programs = {r.get("SYSLOG_IDENTIFIER") for r in self.records}
		self.assertIn("sshd", programs, "synthetic sshd records missing")
		self.assertIn("sudo", programs, "real sudo records missing")

	def test_pid_falls_back_to_underscore_pid(self):
		"""sudo's COMMAND record carries no SYSLOG_PID — verified on this box.

		Without the `_PID` fallback every sudo row loses its pid, and with it any
		hope of tying the command back to the session that ran it.
		"""
		command_records = [
			r
			for r in self.records
			if r.get("SYSLOG_IDENTIFIER") == "sudo" and "COMMAND=" in str(r.get("MESSAGE", ""))
		]
		self.assertTrue(command_records, "fixture lost its sudo COMMAND records")
		for record in command_records:
			self.assertNotIn("SYSLOG_PID", record, "fixture no longer exercises the fallback")
			line = journal_record_to_syslog_line(record)
			self.assertIsNotNone(line.pid)
			self.assertEqual(line.pid, int(record["_PID"]))

	def test_timestamp_is_utc_from_realtime_microseconds(self):
		record = self.records[0]
		line = journal_record_to_syslog_line(record)
		self.assertEqual(line.timestamp.tzinfo, UTC)
		self.assertEqual(int(line.timestamp.timestamp() * 1_000_000), int(record["__REALTIME_TIMESTAMP"]))

	def test_boot_id_scopes_the_session_key(self):
		"""Pid reuse across a reboot must not merge two unrelated logins."""
		record = next(r for r in self.records if r.get("SYSLOG_IDENTIFIER") == "sshd")
		event = parse_journal_record(record)
		self.assertIsNotNone(event.session_key)
		self.assertTrue(event.session_key.startswith(record["_BOOT_ID"][:12]))

		rebooted = dict(record, _BOOT_ID="ffffffffffffffffffffffffffffffff")
		self.assertNotEqual(parse_journal_record(rebooted).session_key, event.session_key)

	def test_audit_session_is_carried_through(self):
		record = next(r for r in self.records if r.get("_AUDIT_SESSION"))
		line = journal_record_to_syslog_line(record)
		self.assertEqual(line.audit_session, record["_AUDIT_SESSION"])

	def test_byte_list_message_is_decoded_not_crashed(self):
		"""journald emits MESSAGE as a byte array when the payload is not UTF-8."""
		record = next(r for r in self.records if isinstance(r.get("MESSAGE"), list))
		line = journal_record_to_syslog_line(record)
		self.assertIsInstance(line.message, str)
		self.assertIn("Bad protocol version", line.message)

	def test_malformed_records_return_none(self):
		for record in ({}, {"MESSAGE": "x"}, {"__REALTIME_TIMESTAMP": "nope", "MESSAGE": "x"}):
			self.assertIsNone(parse_journal_record(record), f"expected None for {record!r}")


class TestTransportEquivalence(unittest.TestCase):
	"""The same event, delivered both ways, must produce the same verdict."""

	#: (journald MESSAGE, the auth.log line carrying the identical body)
	PAIRS: ClassVar[list[tuple[str, str]]] = [
		(
			"Accepted password for patoo from 203.0.113.24 port 51234 ssh2",
			"2026-08-24T09:15:01.100000+00:00 hetzner-prod sshd[4021]: "
			"Accepted password for patoo from 203.0.113.24 port 51234 ssh2",
		),
		(
			"Failed password for invalid user admin from 45.61.187.3 port 33346 ssh2",
			"2026-08-24T09:20:12.000000+00:00 hetzner-prod sshd[4101]: "
			"Failed password for invalid user admin from 45.61.187.3 port 33346 ssh2",
		),
		(
			"pam_unix(sshd:session): session closed for user patoo",
			"2026-08-24T09:47:55.900000+00:00 hetzner-prod sshd[4021]: "
			"pam_unix(sshd:session): session closed for user patoo",
		),
	]

	#: Fields that legitimately differ by transport and are excluded from the
	#: comparison: the session key embeds the boot id (journald only), and the
	#: timestamps come from different clocks by design.
	TRANSPORT_SPECIFIC: ClassVar[set[str]] = {"session_key", "audit_session", "event_time", "hostname"}

	def _journal_record(self, message: str, pid: int) -> dict:
		return {
			"MESSAGE": message,
			"SYSLOG_IDENTIFIER": "sshd",
			"SYSLOG_PID": str(pid),
			"_PID": str(pid),
			"_HOSTNAME": "hetzner-prod",
			"_BOOT_ID": "53f2959a7a9d41c482b2393416d0402a",
			"__REALTIME_TIMESTAMP": "1787148871683212",
		}

	def test_semantic_fields_match_across_transports(self):
		for message, raw_line in self.PAIRS:
			with self.subTest(message=message):
				pid = int(raw_line.split("sshd[")[1].split("]")[0])
				from_journal = parse_journal_record(self._journal_record(message, pid))
				from_text = parse_log_line(raw_line)

				self.assertIsInstance(from_journal, AuthEvent)
				self.assertIsInstance(from_text, AuthEvent)
				for field in AuthEvent.__dataclass_fields__:
					if field in self.TRANSPORT_SPECIFIC:
						continue
					self.assertEqual(
						getattr(from_journal, field),
						getattr(from_text, field),
						f"field {field!r} differs between transports for {message!r}",
					)

	def test_sudo_matches_across_transports(self):
		message = "   patoo : TTY=pts/0 ; PWD=/home/patoo ; USER=root ; COMMAND=/usr/bin/id"
		from_journal = parse_journal_record(
			dict(self._journal_record(message, 3121), SYSLOG_IDENTIFIER="sudo")
		)
		from_text = parse_log_line(f"2026-08-24T10:11:53.398705+00:00 hetzner-prod sudo: {message}")

		self.assertIsInstance(from_journal, SudoEvent)
		self.assertIsInstance(from_text, SudoEvent)
		for field in ("actor", "target_user", "tty", "pwd", "command", "status"):
			self.assertEqual(
				getattr(from_journal, field), getattr(from_text, field), f"field {field!r} differs"
			)

	def test_every_synthetic_sshd_journal_record_parses(self):
		"""The canary again, this time on the journald path."""
		unparsed = [
			r["MESSAGE"]
			for r in read_journal()
			if r.get("SYSLOG_IDENTIFIER") in parser.SSHD_PROGRAMS and parse_journal_record(r) is None
		]
		self.assertEqual(unparsed, [], "sshd journal records matched no rule")


if __name__ == "__main__":
	unittest.main()
