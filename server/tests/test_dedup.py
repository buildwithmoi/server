# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Dedup-hash tests.

The hash is a UNIQUE column, and it is the correctness backstop for the whole
ingest: the checkpoint is the fast path, but a crash between "rows committed"
and "checkpoint committed" replays a window, and a lost journal cursor replays
up to `bootstrap_hours` of it. Both are absorbed here or not at all.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta, timezone

from server.ssh.parser import dedup_hash, event_dedup_hash, journal_record_to_syslog_line, parse_syslog_line


class TestDedupHashStability(unittest.TestCase):
	def test_same_inputs_give_same_hash(self):
		args = (datetime(2026, 8, 24, 9, 15, 1, tzinfo=UTC), "h", "sshd", 4021, "Accepted password")
		self.assertEqual(dedup_hash(*args), dedup_hash(*args))

	def test_hash_is_forty_hex_characters(self):
		value = dedup_hash(datetime(2026, 8, 24, tzinfo=UTC), "h", "sshd", 1, "x")
		self.assertEqual(len(value), 40)
		self.assertTrue(all(c in "0123456789abcdef" for c in value))

	def test_different_message_gives_different_hash(self):
		base = datetime(2026, 8, 24, 9, 15, 1, tzinfo=UTC)
		self.assertNotEqual(
			dedup_hash(base, "h", "sshd", 1, "Failed password for a from 1.2.3.4 port 1 ssh2"),
			dedup_hash(base, "h", "sshd", 1, "Failed password for a from 1.2.3.4 port 2 ssh2"),
		)

	def test_different_pid_gives_different_hash(self):
		base = datetime(2026, 8, 24, 9, 15, 1, tzinfo=UTC)
		self.assertNotEqual(dedup_hash(base, "h", "sshd", 1, "x"), dedup_hash(base, "h", "sshd", 2, "x"))

	def test_missing_pid_is_stable(self):
		"""sudo COMMAND records have no pid in auth.log — None must not vary."""
		base = datetime(2026, 8, 24, 9, 15, 1, tzinfo=UTC)
		self.assertEqual(dedup_hash(base, "h", "sudo", None, "x"), dedup_hash(base, "h", "sudo", None, "x"))

	def test_non_utf8_message_does_not_raise(self):
		base = datetime(2026, 8, 24, tzinfo=UTC)
		self.assertEqual(len(dedup_hash(base, "h", "sshd", 1, "bad \udcff bytes")), 40)


class TestSubSecondTolerance(unittest.TestCase):
	"""The design decision that makes cross-source dedup work at all."""

	def test_microsecond_skew_collapses_to_one_hash(self):
		"""journald and rsyslog stamp the same event microseconds apart.

		journald records when the journal accepted it; rsyslog records when
		rsyslog accepted it. Truncating to the second is what lets the two
		ingest paths agree they have seen the same thing.
		"""
		base = datetime(2026, 8, 24, 9, 15, 1, 100000, tzinfo=UTC)
		skewed = base + timedelta(microseconds=873)
		self.assertEqual(
			dedup_hash(base, "h", "sshd", 4021, "Accepted password for patoo from 1.2.3.4 port 1 ssh2"),
			dedup_hash(skewed, "h", "sshd", 4021, "Accepted password for patoo from 1.2.3.4 port 1 ssh2"),
		)

	def test_a_full_second_apart_is_a_different_event(self):
		base = datetime(2026, 8, 24, 9, 15, 1, tzinfo=UTC)
		self.assertNotEqual(
			dedup_hash(base, "h", "sshd", 1, "x"),
			dedup_hash(base + timedelta(seconds=1), "h", "sshd", 1, "x"),
		)


class TestCrossTransportDedup(unittest.TestCase):
	def test_journald_and_authlog_agree_on_the_same_event(self):
		"""The property the whole re-read strategy rests on."""
		message = "Accepted password for patoo from 203.0.113.24 port 51234 ssh2"
		stamp = datetime(2026, 8, 24, 9, 15, 1, 100000, tzinfo=UTC)

		from_journal = journal_record_to_syslog_line(
			{
				"MESSAGE": message,
				"SYSLOG_IDENTIFIER": "sshd",
				"SYSLOG_PID": "4021",
				"_HOSTNAME": "hetzner-prod",
				"_BOOT_ID": "53f2959a7a9d41c482b2393416d0402a",
				# journald saw it 873µs after rsyslog did.
				"__REALTIME_TIMESTAMP": str(int(stamp.timestamp() * 1_000_000) + 873),
			}
		)
		from_text = parse_syslog_line(f"{stamp.isoformat()} hetzner-prod sshd[4021]: {message}")

		self.assertEqual(event_dedup_hash(from_journal), event_dedup_hash(from_text))


if __name__ == "__main__":
	unittest.main()
