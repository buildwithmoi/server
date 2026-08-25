# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Argument validation for the repository probe.

`shell=False` is not the protection it looks like. git takes options that name
a command to run, so a remote string beginning with `-` becomes an argument of
git's choosing rather than ours:

    git ls-remote --heads "--upload-pack=touch /tmp/x; git-upload-pack" /some/repo

executes `touch` and exits 0 — and because refs then parse, the probe reported
`reachable: true`. This was reachable from a whitelisted endpoint that also
skipped the install interlock, so it ran as the bench user with the app's own
kill switch turned off.

These tests never spawn git. They assert the refusal happens before the argv is
built, which is the only place it can be relied on.
"""

from __future__ import annotations

import unittest

try:
	import frappe  # noqa: F401

	from server.bench import doctor

	_AVAILABLE = True
except Exception:  # pragma: no cover
	_AVAILABLE = False


@unittest.skipUnless(_AVAILABLE, "requires frappe on the path")
class TestRemoteValidation(unittest.TestCase):
	def test_option_lookalikes_are_refused(self):
		"""The actual exploit, and its neighbours."""
		for url in (
			"--upload-pack=touch /tmp/pwned; git-upload-pack",
			"--exec=touch /tmp/pwned",
			"-u",
			"--config=core.gitProxy=touch",
		):
			with self.subTest(url=url), self.assertRaises(doctor.RepoRefused):
				doctor.check_repo(url)

	def test_transports_that_run_a_command_are_refused(self):
		"""git's `ext::` transport is a shell by another name."""
		for url in ("ext::sh -c touch% /tmp/pwned", "ext::bash -c id"):
			with self.subTest(url=url), self.assertRaises(doctor.RepoRefused):
				doctor.check_repo(url)

	def test_local_paths_are_refused(self):
		"""A local path is what makes the --upload-pack trick fire at all."""
		for url in ("/etc/passwd", "/home/patoo/fb-16-server/apps/frappe", "file:///tmp", "."):
			with self.subTest(url=url), self.assertRaises(doctor.RepoRefused):
				doctor.check_repo(url)

	def test_empty_and_junk_are_refused(self):
		for url in ("", "   ", "not a url", "http://insecure.example.com/x"):
			with self.subTest(url=url), self.assertRaises(doctor.RepoRefused):
				doctor.check_repo(url)

	def test_the_remotes_this_app_actually_uses_are_accepted(self):
		"""The regex must not be so tight that it refuses real work.

		Asserted by matching the pattern rather than by running git, so this
		does not depend on the network.
		"""
		for url in (
			"git@github.com:Carbonite-Solutions-Ltd/server.git",
			"git@github-carbonite:Org/repo.git",
			"ssh://git@github.com/Org/repo.git",
			"https://github.com/frappe/frappe.git",
		):
			with self.subTest(url=url):
				self.assertTrue(doctor.VALID_REMOTE.match(url), f"{url} should be allowed")


@unittest.skipUnless(_AVAILABLE, "requires frappe on the path")
class TestBranchValidation(unittest.TestCase):
	def test_a_branch_cannot_be_an_option(self):
		for branch in ("--upload-pack=touch /tmp/pwned", "-o=x", "--exec=id"):
			with self.subTest(branch=branch), self.assertRaises(doctor.RepoRefused):
				doctor.check_repo("git@github.com:Org/repo.git", branch)

	def test_real_branch_names_are_accepted(self):
		for branch in ("main", "version-16", "feature/thing", "release_1.2.3"):
			with self.subTest(branch=branch):
				self.assertTrue(doctor.VALID_BRANCH.match(branch))

	def test_a_branch_must_begin_alphanumeric(self):
		"""Which is what makes "cannot be an option" structural rather than a
		blocklist of the options that exist today."""
		self.assertIsNone(doctor.VALID_BRANCH.match("-main"))
		self.assertIsNone(doctor.VALID_BRANCH.match(".main"))


if __name__ == "__main__":
	unittest.main()
