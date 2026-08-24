# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""sudo rule tests.

Unlike the sshd fixtures, every line exercised here is REAL — sudo is the one
authentication signal this WSL development box genuinely produces, and it is
also the richest "what did they actually do" record available on the target
server without installing auditd.
"""

from __future__ import annotations

import unittest

from server.ssh import parser
from server.ssh.parser import parse_log_line, parse_syslog_line
from server.tests._support import read_lines


def _event(body: str, host: str = "hetzner-prod"):
	return parse_log_line(f"2026-08-24T10:11:53.398705+00:00 {host} sudo: {body}")


class TestSudoCommand(unittest.TestCase):
	def test_successful_invocation(self):
		ev = _event(
			"   patoo : TTY=pts/0 ; PWD=/home/patoo/fb-15-1 ; USER=root ; COMMAND=/usr/bin/supervisorctl status"
		)
		self.assertEqual(ev.status, parser.SUDO_EXECUTED)
		self.assertEqual(ev.actor, "patoo")
		self.assertEqual(ev.target_user, "root")
		self.assertEqual(ev.tty, "pts/0")
		self.assertEqual(ev.pwd, "/home/patoo/fb-15-1")
		self.assertEqual(ev.command, "/usr/bin/supervisorctl status")
		self.assertIsNone(ev.failure_reason)

	def test_command_containing_shell_metacharacters(self):
		"""The command is the rest of the line — semicolons in it must not split it."""
		ev = _event(
			'   patoo : TTY=pts/1 ; PWD=/home/patoo ; USER=root ; COMMAND=/bin/sh -c "cd /tmp && ./x; echo done"'
		)
		self.assertEqual(ev.command, '/bin/sh -c "cd /tmp && ./x; echo done"')
		self.assertEqual(ev.status, parser.SUDO_EXECUTED)

	def test_non_root_target(self):
		ev = _event(
			"   deploy : TTY=unknown ; PWD=/ ; USER=www-data ; COMMAND=/usr/bin/systemctl restart nginx"
		)
		self.assertEqual(ev.target_user, "www-data")
		self.assertEqual(ev.actor, "deploy")


class TestSudoDenied(unittest.TestCase):
	def test_password_required_replaces_the_tty_clause(self):
		"""On refusal sudo swaps TTY=… for free text — a real line from this box."""
		ev = _event(
			"   patoo : a password is required ; PWD=/home/patoo/fb-16-res/apps/bwm_pos ; USER=root ; COMMAND=/usr/bin/true"
		)
		self.assertEqual(ev.status, parser.SUDO_DENIED)
		self.assertEqual(ev.failure_reason, "a password is required")
		self.assertEqual(ev.actor, "patoo")
		self.assertEqual(ev.command, "/usr/bin/true")
		self.assertIsNone(ev.tty)

	def test_user_not_in_sudoers(self):
		ev = _event("  intruder : user NOT in sudoers ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
		self.assertEqual(ev.status, parser.SUDO_DENIED)
		self.assertEqual(ev.actor, "intruder")
		self.assertEqual(ev.failure_reason, "user NOT in sudoers")


class TestSudoAuthFailure(unittest.TestCase):
	def test_conversation_failed(self):
		ev = _event("pam_unix(sudo:auth): conversation failed")
		self.assertEqual(ev.status, parser.SUDO_AUTH_FAILURE)
		self.assertEqual(ev.failure_reason, "conversation failed")

	def test_could_not_identify_password(self):
		ev = _event("pam_unix(sudo:auth): auth could not identify password for [patoo]")
		self.assertEqual(ev.status, parser.SUDO_AUTH_FAILURE)
		self.assertIn("patoo", ev.failure_reason)


class TestSudoNoise(unittest.TestCase):
	def test_session_pairs_are_deliberately_ignored(self):
		"""Two rows of pure noise per real row is not a trade worth making.

		The COMMAND record already carries the actor, the target and the command;
		pam_unix(sudo:session) carries none of them.
		"""
		for body in (
			"pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
			"pam_unix(sudo:session): session closed for user root",
		):
			with self.subTest(body=body):
				self.assertIsNone(_event(body))


class TestNonSudoProgramsAreNotClaimed(unittest.TestCase):
	def test_cron_and_login_pam_lines_are_ignored(self):
		"""CRON alone is ~76% of this box's auth volume — it must never become a row."""
		for raw in read_lines("auth_rfc3339.log"):
			line = parse_syslog_line(raw)
			if line is None or line.program in parser.SSHD_PROGRAMS | parser.SUDO_PROGRAMS:
				continue
			self.assertIsNone(
				parser.parse_syslog_record(line),
				f"{line.program} should not produce an event: {line.message!r}",
			)


if __name__ == "__main__":
	unittest.main()
