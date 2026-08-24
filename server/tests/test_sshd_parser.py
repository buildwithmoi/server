# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""sshd rule-table tests.

Every sshd line in the fixtures is synthetic — this development box has no
openssh-server at all. The message bodies come from the OpenSSH 9.x catalogue
encoded in /etc/fail2ban/filter.d/sshd.conf, which is what fail2ban matches
against in production and is therefore the closest thing to ground truth
available without the real server.
"""

from __future__ import annotations

import unittest

from server.ssh import parser
from server.ssh.parser import parse_log_line, parse_syslog_line
from server.tests._support import read_lines


def _event(body: str, pid: int = 4021, host: str = "hetzner-prod"):
	return parse_log_line(f"2026-08-24T09:15:01.100000+00:00 {host} sshd[{pid}]: {body}")


class TestAcceptedLogins(unittest.TestCase):
	def test_password(self):
		ev = _event("Accepted password for patoo from 203.0.113.24 port 51234 ssh2")
		self.assertEqual(ev.event_type, parser.EVENT_ACCEPTED)
		self.assertEqual(ev.outcome, parser.OUTCOME_SUCCESS)
		self.assertEqual(ev.username, "patoo")
		self.assertEqual(ev.auth_method, "password")
		self.assertEqual(ev.source_ip, "203.0.113.24")
		self.assertEqual(ev.source_port, 51234)
		self.assertFalse(ev.invalid_user)

	def test_publickey_captures_fingerprint(self):
		ev = _event(
			"Accepted publickey for patoo from 203.0.113.24 port 51234 ssh2: "
			"RSA SHA256:pQr9vTn0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678"
		)
		self.assertEqual(ev.auth_method, "publickey")
		self.assertEqual(ev.key_fingerprint, "RSA SHA256:pQr9vTn0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678")

	def test_unusual_methods_are_not_dropped(self):
		"""auth_method is free text on purpose — an enum would silently drop these."""
		for body, expected in (
			(
				"Accepted keyboard-interactive/pam for patoo from 203.0.113.24 port 1 ssh2",
				"keyboard-interactive/pam",
			),
			("Accepted gssapi-with-mic for patoo from 203.0.113.24 port 1 ssh2", "gssapi-with-mic"),
			("Accepted none for guest from 203.0.113.24 port 1 ssh2", "none"),
		):
			with self.subTest(body=body):
				self.assertEqual(_event(body).auth_method, expected)

	def test_ipv6_source(self):
		ev = _event(
			"Accepted publickey for patoo from 2a01:4f8:1c1c:abcd::1 port 51260 ssh2: ED25519 SHA256:abc"
		)
		self.assertEqual(ev.source_ip, "2a01:4f8:1c1c:abcd::1")
		self.assertEqual(ev.source_port, 51260)


class TestFailedLogins(unittest.TestCase):
	def test_failed_password_for_real_user(self):
		ev = _event("Failed password for patoo from 45.61.187.3 port 33344 ssh2")
		self.assertEqual(ev.event_type, parser.EVENT_FAILED)
		self.assertEqual(ev.outcome, parser.OUTCOME_FAILURE)
		self.assertEqual(ev.username, "patoo")
		self.assertFalse(ev.invalid_user)

	def test_failed_password_for_invalid_user(self):
		"""The `invalid user` infix must not be swallowed into the username."""
		ev = _event("Failed password for invalid user admin from 45.61.187.3 port 33346 ssh2")
		self.assertEqual(ev.username, "admin")
		self.assertTrue(ev.invalid_user)

	def test_invalid_user(self):
		ev = _event("Invalid user oracle from 45.61.187.3 port 33350")
		self.assertEqual(ev.event_type, parser.EVENT_INVALID_USER)
		self.assertEqual(ev.username, "oracle")
		self.assertTrue(ev.invalid_user)

	def test_invalid_user_with_empty_username(self):
		"""sshd emits a blank username when the client sends none."""
		ev = _event("Invalid user  from 45.61.187.3 port 33352")
		self.assertEqual(ev.event_type, parser.EVENT_INVALID_USER)
		self.assertIsNone(ev.username)
		self.assertEqual(ev.source_ip, "45.61.187.3")

	def test_pam_auth_failure_extracts_rhost(self):
		ev = _event(
			"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
			"tty=ssh ruser= rhost=45.61.187.3  user=patoo"
		)
		self.assertEqual(ev.event_type, parser.EVENT_FAILED)
		self.assertEqual(ev.source_ip, "45.61.187.3")
		self.assertEqual(ev.username, "patoo")

	def test_pam_auth_failure_without_user(self):
		ev = _event(
			"pam_unix(sshd:auth): authentication failure; logname= uid=0 tty=ssh ruser= rhost=45.61.187.3"
		)
		self.assertEqual(ev.source_ip, "45.61.187.3")
		self.assertIsNone(ev.username)

	def test_max_attempts_exceeded(self):
		ev = _event(
			"maximum authentication attempts exceeded for root from 45.61.187.3 port 33354 ssh2 [preauth]"
		)
		self.assertEqual(ev.event_type, parser.EVENT_FAILED)
		self.assertEqual(ev.username, "root")
		self.assertEqual(ev.source_ip, "45.61.187.3")


class TestDecorationStripping(unittest.TestCase):
	"""OpenSSH wraps the same body in optional prefixes and suffixes."""

	def test_error_prefix_does_not_change_the_verdict(self):
		plain = _event("maximum authentication attempts exceeded for root from 45.61.187.3 port 1 ssh2")
		decorated = _event(
			"error: maximum authentication attempts exceeded for root from 45.61.187.3 port 1 ssh2"
		)
		self.assertEqual(plain.event_type, decorated.event_type)
		self.assertEqual(plain.username, decorated.username)
		self.assertEqual(plain.source_ip, decorated.source_ip)

	def test_pam_prefix_is_stripped(self):
		ev = _event("error: PAM: ROOT LOGIN REFUSED FROM 45.61.187.3 port 33360")
		self.assertEqual(ev.event_type, parser.EVENT_REFUSED)
		self.assertEqual(ev.source_ip, "45.61.187.3")

	def test_preauth_suffix_is_stripped(self):
		ev = _event("Disconnected from invalid user admin 45.61.187.3 port 33362 [preauth]")
		self.assertEqual(ev.event_type, parser.EVENT_DISCONNECTED)
		self.assertEqual(ev.username, "admin")
		self.assertEqual(ev.source_ip, "45.61.187.3")

	def test_port_survives_stripping(self):
		"""The port is extracted before the suffix stripper throws it away."""
		ev = _event("Disconnected from invalid user admin 45.61.187.3 port 33362 [preauth]")
		self.assertEqual(ev.source_port, 33362)


class TestRefusalsAndDisconnects(unittest.TestCase):
	def test_root_login_refused(self):
		ev = _event("ROOT LOGIN REFUSED FROM 45.61.187.3")
		self.assertEqual(ev.event_type, parser.EVENT_REFUSED)
		self.assertEqual(ev.outcome, parser.OUTCOME_FAILURE)

	def test_not_in_allowusers(self):
		ev = _event("User backup from 45.61.187.3 not allowed because not listed in AllowUsers")
		self.assertEqual(ev.event_type, parser.EVENT_REFUSED)
		self.assertEqual(ev.username, "backup")

	def test_clean_disconnect_is_info_not_failure(self):
		ev = _event("Disconnected from user patoo 203.0.113.24 port 51234")
		self.assertEqual(ev.event_type, parser.EVENT_DISCONNECTED)
		self.assertEqual(ev.outcome, parser.OUTCOME_INFO)
		self.assertEqual(ev.username, "patoo")

	def test_preauth_close_is_a_failure(self):
		ev = _event("Connection closed by authenticating user root 45.61.187.3 port 33364 [preauth]")
		self.assertEqual(ev.outcome, parser.OUTCOME_FAILURE)
		self.assertEqual(ev.username, "root")

	def test_received_disconnect(self):
		ev = _event("Received disconnect from 203.0.113.24 port 51234:11: disconnected by user")
		self.assertEqual(ev.event_type, parser.EVENT_DISCONNECTED)
		self.assertEqual(ev.source_ip, "203.0.113.24")


class TestSessionLifecycle(unittest.TestCase):
	def test_session_opened(self):
		ev = _event("pam_unix(sshd:session): session opened for user patoo(uid=1000) by (uid=0)")
		self.assertEqual(ev.event_type, parser.EVENT_SESSION_OPENED)
		self.assertEqual(ev.username, "patoo", "the (uid=…) suffix must not leak into the username")

	def test_session_closed(self):
		ev = _event("pam_unix(sshd:session): session closed for user patoo")
		self.assertEqual(ev.event_type, parser.EVENT_SESSION_CLOSED)
		self.assertEqual(ev.username, "patoo")

	def test_session_key_groups_one_connection(self):
		"""sshd forks per connection, so its pid IS the correlation key."""
		accept = _event("Accepted password for patoo from 203.0.113.24 port 1 ssh2", pid=4021)
		close = _event("pam_unix(sshd:session): session closed for user patoo", pid=4021)
		other = _event("Accepted password for patoo from 203.0.113.24 port 1 ssh2", pid=4099)
		self.assertEqual(accept.session_key, close.session_key)
		self.assertNotEqual(accept.session_key, other.session_key)


class TestBotNoise(unittest.TestCase):
	def test_no_identification_string(self):
		ev = _event("Did not receive identification string from 185.243.96.11 port 44000")
		self.assertEqual(ev.event_type, parser.EVENT_PROTOCOL_ERROR)
		self.assertEqual(ev.source_ip, "185.243.96.11")

	def test_bad_protocol_version(self):
		ev = _event("Bad protocol version identification 'GET / HTTP/1.1' from 185.243.96.11 port 44002")
		self.assertEqual(ev.event_type, parser.EVENT_PROTOCOL_ERROR)
		self.assertEqual(ev.source_ip, "185.243.96.11")

	def test_kex_exchange_identification(self):
		ev = _event("kex_exchange_identification: Connection closed by remote host")
		self.assertEqual(ev.event_type, parser.EVENT_PROTOCOL_ERROR)


class TestPreauthOutcome(unittest.TestCase):
	"""`[preauth]` is stripped before rule matching, so it is read separately."""

	def test_preauth_disconnect_counts_as_a_failure(self):
		"""A scanner opening and dropping a socket is not a clean logout."""
		ev = _event("Disconnected from 45.61.187.3 port 33368 [preauth]")
		self.assertEqual(ev.event_type, parser.EVENT_DISCONNECTED)
		self.assertEqual(ev.outcome, parser.OUTCOME_FAILURE)

	def test_post_auth_disconnect_stays_info(self):
		ev = _event("Disconnected from user patoo 203.0.113.24 port 51234")
		self.assertEqual(ev.outcome, parser.OUTCOME_INFO)

	def test_preauth_does_not_upgrade_a_success(self):
		ev = _event("Accepted password for patoo from 203.0.113.24 port 51234 ssh2")
		self.assertEqual(ev.outcome, parser.OUTCOME_SUCCESS)


class TestTooManyAuthFailures(unittest.TestCase):
	"""On a brute force this is the highest-value line in the log."""

	def test_attacking_ip_and_user_are_kept(self):
		ev = _event(
			"Disconnecting authenticating user root 45.61.187.3 port 33358: Too many authentication failures [preauth]"
		)
		self.assertEqual(ev.event_type, parser.EVENT_FAILED)
		self.assertEqual(ev.outcome, parser.OUTCOME_FAILURE)
		self.assertEqual(ev.username, "root")
		self.assertEqual(ev.source_ip, "45.61.187.3", "the attacking IP must never be dropped")
		self.assertEqual(ev.source_port, 33358)

	def test_older_bare_form_still_parses(self):
		ev = _event("Disconnecting: Too many authentication failures for root [preauth]")
		self.assertEqual(ev.event_type, parser.EVENT_FAILED)
		self.assertEqual(ev.username, "root")


class TestKexIdentification(unittest.TestCase):
	def test_without_peer(self):
		ev = _event("kex_exchange_identification: Connection closed by remote host")
		self.assertEqual(ev.event_type, parser.EVENT_PROTOCOL_ERROR)
		self.assertIsNone(ev.source_ip)

	def test_with_peer_address(self):
		ev = _event("kex_exchange_identification: read: Connection reset by 185.243.96.11")
		self.assertEqual(ev.source_ip, "185.243.96.11")


class TestNoSSHDLineIsUnparsed(unittest.TestCase):
	"""The canary. If someone adds a format to a fixture without a rule, this fails.

	This is the most valuable test in the suite: it is the only mechanism that
	turns "I forgot a message variant" into a red build rather than into rows
	that silently never appear in the intrusion view.
	"""

	def _assert_all_sshd_parse(self, fixture: str):
		unparsed = []
		for raw in read_lines(fixture):
			line = parse_syslog_line(raw)
			if line is None or line.program not in parser.SSHD_PROGRAMS:
				continue
			if parser.parse_sshd_message(line) is None:
				unparsed.append(line.message)
		self.assertEqual(unparsed, [], f"{len(unparsed)} sshd line(s) in {fixture} matched no rule")

	def test_rfc3339_fixture(self):
		self._assert_all_sshd_parse("auth_rfc3339.log")

	def test_classic_fixture(self):
		self._assert_all_sshd_parse("auth_classic.log")

	def test_both_prefix_styles_agree(self):
		"""The same events in both formats must parse identically bar the year."""
		rfc = [parse_log_line(x) for x in read_lines("auth_rfc3339.log")]
		classic = [parse_log_line(x) for x in read_lines("auth_classic.log")]
		self.assertEqual(len(rfc), len(classic))
		for a, b in zip(rfc, classic, strict=True):
			if a is None or b is None:
				self.assertIs(type(a), type(b))
				continue
			self.assertEqual(a.raw_message, b.raw_message)
			self.assertEqual(
				getattr(a, "event_type", None) or a.status,
				getattr(b, "event_type", None) or b.status,
			)


if __name__ == "__main__":
	unittest.main()
