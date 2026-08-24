# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Prefix-layer tests: everything before the message body."""

from __future__ import annotations

import unittest
from datetime import datetime

from server.ssh.parser import parse_syslog_line
from server.tests._support import read_lines


class TestRFC3339Prefix(unittest.TestCase):
	def test_program_with_pid(self):
		line = parse_syslog_line(
			"2026-08-24T09:15:01.100000+00:00 hetzner-prod sshd[4021]: Accepted password for patoo"
		)
		self.assertIsNotNone(line)
		self.assertEqual(line.hostname, "hetzner-prod")
		self.assertEqual(line.program, "sshd")
		self.assertEqual(line.pid, 4021)
		self.assertEqual(line.message, "Accepted password for patoo")
		self.assertEqual(line.timestamp.year, 2026)

	def test_program_without_pid(self):
		"""`sudo:` emits no pid bracket — verified on this box."""
		line = parse_syslog_line(
			"2026-08-24T10:11:53.398705+00:00 DESKTOP-G6V9TKR sudo:    patoo : TTY=pts/0 ; USER=root"
		)
		self.assertIsNotNone(line)
		self.assertEqual(line.program, "sudo")
		self.assertIsNone(line.pid)
		# The leading whitespace of sudo's body must survive — the sudo grammar
		# depends on it being there.
		self.assertTrue(line.message.startswith("   patoo :"))

	def test_hyphenated_program(self):
		line = parse_syslog_line(
			"2026-08-23T06:44:06.125231+00:00 DESKTOP-G6V9TKR systemd-logind[185]: New session 1 of user patoo."
		)
		self.assertEqual(line.program, "systemd-logind")
		self.assertEqual(line.pid, 185)

	def test_parenthesised_program(self):
		line = parse_syslog_line(
			"2026-08-23T06:44:06.221166+00:00 DESKTOP-G6V9TKR (systemd): pam_unix(systemd-user:session): opened"
		)
		self.assertEqual(line.program, "(systemd)")
		self.assertIsNone(line.pid)

	def test_utc_designator(self):
		line = parse_syslog_line("2026-08-24T09:15:01Z host sshd[1]: Connection from 1.2.3.4")
		self.assertIsNotNone(line)
		self.assertEqual(line.timestamp.hour, 9)


class TestClassicPrefix(unittest.TestCase):
	def test_classic_line(self):
		line = parse_syslog_line(
			"Aug 24 09:15:01 hetzner-prod sshd[4021]: Accepted password for patoo",
			now=datetime(2026, 8, 24, 12, 0, 0),
		)
		self.assertIsNotNone(line)
		self.assertEqual(line.program, "sshd")
		self.assertEqual(line.pid, 4021)
		self.assertEqual(line.timestamp, datetime(2026, 8, 24, 9, 15, 1))

	def test_single_digit_day_is_space_padded(self):
		line = parse_syslog_line(
			"Aug  3 09:15:01 host sshd[1]: Connection from 1.2.3.4",
			now=datetime(2026, 8, 24, 12, 0, 0),
		)
		self.assertEqual(line.timestamp.day, 3)

	def test_year_rolls_back_across_new_year(self):
		"""A December line read on 2 January belongs to LAST year.

		Without this the row is dated eleven months in the future and pins
		itself to the top of a creation-DESC list view forever.
		"""
		line = parse_syslog_line(
			"Dec 31 23:59:59 host sshd[1]: Connection from 1.2.3.4",
			now=datetime(2027, 1, 2, 10, 0, 0),
		)
		self.assertEqual(line.timestamp.year, 2026)

	def test_same_year_when_not_in_future(self):
		line = parse_syslog_line(
			"Jan 02 10:00:00 host sshd[1]: Connection from 1.2.3.4",
			now=datetime(2027, 1, 2, 12, 0, 0),
		)
		self.assertEqual(line.timestamp.year, 2027)


class TestPrefixRejection(unittest.TestCase):
	def test_blank_and_comment_lines_return_none(self):
		for raw in ("", "   ", "\n", "# a comment", "   # indented comment"):
			self.assertIsNone(parse_syslog_line(raw), f"expected None for {raw!r}")

	def test_garbage_returns_none_rather_than_raising(self):
		for raw in ("not a log line at all", "2026-13-45T99:99:99+00:00 h p: x", "<<< binary junk >>>"):
			self.assertIsNone(parse_syslog_line(raw), f"expected None for {raw!r}")

	def test_every_fixture_line_is_either_parsed_or_a_comment(self):
		"""No meaningful line in the RFC3339 fixture may fail the prefix layer."""
		for raw in read_lines("auth_rfc3339.log"):
			self.assertIsNotNone(parse_syslog_line(raw), f"prefix layer rejected: {raw!r}")


if __name__ == "__main__":
	unittest.main()
