# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Who can log in, and the rogue account that sat there for months.

The headline is `TestTheRogueAccount`: the incident left a `mysqld` account —
UID 1003, a bash shell, no home directory — in /etc/passwd, reading as the
MariaDB service account to anyone glancing at the file. Nothing ever mentioned
it because nothing was looking.

The rest of this file is the other half of the job: proving the detector is
quiet about the thirty stock accounts a Debian host ships with, because a
detector that flags `daemon` and `www-data` is one nobody reads.

Frappe-free.
"""

from __future__ import annotations

import unittest

from server.security import account_rules as R
from server.security import accounts as A


def worst(findings):
	order = ["Critical", "High", "Medium", "Info"]
	return min((f.severity for f in findings), key=order.index) if findings else None


class TestTheRogueAccount(unittest.TestCase):
	ROGUE = A.Account(
		username="mysqld", uid=1003, gid=1003, shell="/bin/bash",
		home="/home/mysqld", home_exists=False,
	)

	def test_it_is_caught_as_critical(self):
		self.assertEqual(worst(R.judge_account(R.APPEARED, self.ROGUE)), R.CRITICAL)

	def test_it_is_caught_three_independent_ways(self):
		"""Any one alone is worth a look; together they are not something a
		package does."""
		subjects = " ".join(f.subject for f in R.judge_account(R.APPEARED, self.ROGUE))
		self.assertIn("New account", subjects)
		self.assertIn("Service account with a login shell", subjects)
		self.assertIn("no home directory", subjects)

	def test_the_shape_alone_is_enough(self):
		"""It must be caught on a FIRST scan too, where there is nothing to
		diff against — an already-compromised host has no clean 'before'."""
		self.assertEqual(worst(R.shape_findings(self.ROGUE)), R.CRITICAL)

	def test_a_real_service_account_is_quiet(self):
		real = A.Account("mysql", 114, 120, "/usr/sbin/nologin", "/nonexistent")
		self.assertEqual(R.shape_findings(real), [])


class TestPrivilegeSignatures(unittest.TestCase):
	def test_a_second_uid_zero_is_critical(self):
		second = A.Account("backup2", 0, 0, "/bin/bash", "/root", home_exists=True)
		findings = R.shape_findings(second)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertTrue(any("Second root" in f.subject for f in findings))

	def test_root_itself_is_not_flagged(self):
		root = A.Account("root", 0, 0, "/bin/bash", "/root", home_exists=True)
		self.assertEqual(R.shape_findings(root), [])

	def test_being_granted_sudo_is_critical(self):
		before = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob", home_exists=True, groups=("users",))
		after = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob", home_exists=True, groups=("users", "sudo"))
		findings = R.judge_account(R.MODIFIED, after, before)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertTrue(any("granted sudo" in f.subject for f in findings))

	def test_gaining_a_shell_is_critical(self):
		before = A.Account("svc", 999, 999, "/usr/sbin/nologin", "/nonexistent")
		after = A.Account("svc", 999, 999, "/bin/bash", "/nonexistent")
		self.assertEqual(worst(R.judge_account(R.MODIFIED, after, before)), R.CRITICAL)

	def test_losing_a_shell_is_only_high(self):
		"""Usually hardening, not an attack."""
		before = A.Account("svc", 1001, 1001, "/bin/bash", "/home/svc", home_exists=True)
		after = A.Account("svc", 1001, 1001, "/usr/sbin/nologin", "/home/svc", home_exists=True)
		self.assertEqual(worst(R.judge_account(R.MODIFIED, after, before)), R.HIGH)

	def test_a_password_appearing_on_a_key_only_account(self):
		before = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob", home_exists=True,
		                   password_status=A.PASSWORD_LOCKED)
		after = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob", home_exists=True,
		                  password_status=A.PASSWORD_SET)
		self.assertTrue(any("Password set" in f.subject for f in R.judge_account(R.MODIFIED, after, before)))

	def test_a_privileged_account_vanishing_is_critical(self):
		gone = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob", groups=("sudo",))
		self.assertEqual(worst(R.judge_account(R.DISAPPEARED, gone)), R.CRITICAL)

	def test_an_ordinary_account_vanishing_is_not(self):
		gone = A.Account("bob", 1001, 1001, "/bin/bash", "/home/bob")
		self.assertEqual(worst(R.judge_account(R.DISAPPEARED, gone)), R.MEDIUM)


class TestNoiseOnAStockHost(unittest.TestCase):
	"""A detector that flags `daemon` and `www-data` is one nobody reads."""

	def test_this_hosts_real_accounts_produce_nothing(self):
		snapshot = A.collect()
		self.assertTrue(snapshot.accounts, "no accounts were read at all")
		noisy = [
			(account.username, [f.subject for f in R.shape_findings(account)])
			for account in snapshot.accounts
			if R.shape_findings(account)
		]
		self.assertEqual(noisy, [], f"stock accounts produced findings: {noisy}")

	def test_the_stock_sync_account_is_not_a_login_shell(self):
		"""/bin/sync runs sync(1) and exits. Treating it as a shell would flag a
		Debian account on every host, forever."""
		self.assertFalse(A.Account("sync", 4, 65534, "/bin/sync", "/bin").can_log_in)


class TestStaleAccounts(unittest.TestCase):
	ACCOUNT = A.Account("old", 1002, 1002, "/bin/bash", "/home/old", home_exists=True)

	def test_unused_for_months_is_medium_not_critical(self):
		"""Hygiene, not an incident."""
		self.assertEqual(worst(R.judge_stale(self.ACCOUNT, 200)), R.MEDIUM)

	def test_recently_used_is_quiet(self):
		self.assertEqual(R.judge_stale(self.ACCOUNT, 3), [])

	def test_an_account_that_cannot_log_in_is_never_stale(self):
		locked = A.Account("svc", 999, 999, "/usr/sbin/nologin", "/nonexistent")
		self.assertEqual(R.judge_stale(locked, 5000), [])

	def test_an_unknown_last_login_is_not_treated_as_ancient(self):
		self.assertEqual(R.judge_stale(self.ACCOUNT, None), [])


class TestKeys(unittest.TestCase):
	KEY = A.Key("root", "/root/.ssh/authorized_keys", "SHA256:abc", "ssh-ed25519", "someone@vps")

	def test_a_new_key_is_critical(self):
		self.assertEqual(worst(R.judge_key(R.APPEARED, self.KEY)), R.CRITICAL)

	def test_it_says_where_the_key_has_already_been_used(self):
		"""The login records already carry the fingerprint, so this join turns
		'a new key exists' into 'a new key exists and it has been used, from
		here'."""
		detail = R.judge_key(R.APPEARED, self.KEY, used_from=["203.0.113.9"])[0].detail
		self.assertIn("203.0.113.9", detail)

	def test_removal_is_only_medium(self):
		self.assertEqual(worst(R.judge_key(R.DISAPPEARED, self.KEY)), R.MEDIUM)

	def test_the_fingerprint_matches_what_openssh_prints(self):
		"""Computed directly rather than by shelling out to ssh-keygen, so it
		has to agree with it."""
		import base64
		import hashlib

		blob = base64.b64encode(b"not a real key, but a stable one").decode()
		expected = "SHA256:" + base64.b64encode(
			hashlib.sha256(base64.b64decode(blob)).digest()
		).decode().rstrip("=")
		self.assertEqual(A.fingerprint("ssh-ed25519", blob), expected)

	def test_a_malformed_key_line_is_skipped_not_crashed_on(self):
		self.assertEqual(A.parse_authorized_keys("this is not a key\n", "root", "/x"), [])

	def test_options_and_comments_are_captured(self):
		import base64

		blob = base64.b64encode(b"x" * 32).decode()
		line = f'command="/bin/true",no-pty ssh-ed25519 {blob} deploy@ci'
		key = A.parse_authorized_keys(line, "root", "/x")[0]
		self.assertIn("command=", key.options)
		self.assertEqual(key.comment, "deploy@ci")


class TestPasswordHandling(unittest.TestCase):
	"""The hash is read to classify it and immediately discarded. An app that
	watches for compromise must not become the richest target on the estate."""

	SHADOW = [
		"root:$6$averyrealhashvalue$more:19000:0:99999:7:::",
		"locked:!:19000:0:99999:7:::",
		"nopassword::19000:0:99999:7:::",
		"star:*:19000:0:99999:7:::",
	]

	def test_status_is_classified_correctly(self):
		parsed = A.parse_shadow(self.SHADOW)
		self.assertEqual(parsed["root"][0], A.PASSWORD_SET)
		self.assertEqual(parsed["locked"][0], A.PASSWORD_LOCKED)
		self.assertEqual(parsed["nopassword"][0], A.PASSWORD_NONE)
		self.assertEqual(parsed["star"][0], A.PASSWORD_LOCKED)

	def test_no_hash_survives_the_parse(self):
		import json

		blob = json.dumps(A.parse_shadow(self.SHADOW))
		self.assertNotIn("averyrealhashvalue", blob)
		self.assertNotIn("$6$", blob)


class TestCoverage(unittest.TestCase):
	def test_an_unreadable_shadow_names_what_it_costs(self):
		"""Naming the consequence rather than the file is what makes it
		actionable."""
		surfaces = [A.Surface("passwords", "/etc/shadow", False, "permission denied")]
		findings = R.judge_coverage(surfaces)
		self.assertEqual(len(findings), 1)
		self.assertIn("Password status cannot be read", findings[0].detail)

	def test_everything_readable_is_quiet(self):
		self.assertEqual(R.judge_coverage([A.Surface("accounts", "/etc/passwd", True)]), [])


if __name__ == "__main__":
	unittest.main()
