# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Install-time prerequisite checks.

This app declares no third-party Python packages, so `bench get-app` cannot
fail for a missing dependency. It can, however, install perfectly onto a machine
that quietly cannot do the job — and these guard the checks that say so.
"""

from __future__ import annotations

import unittest
from unittest import mock

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestPrerequisites(unittest.TestCase):
	def setUp(self):
		from server import install

		self.install = install
		self.addCleanup(frappe.db.rollback)

	def test_reports_every_command_the_app_shells_out_to(self):
		report = self.install.check_prerequisites()
		self.assertEqual(
			set(report["commands"]) - {"bench"},
			set(self.install.REQUIRED_COMMANDS),
			"every command the app runs must be reported on",
		)
		self.assertIn("bench", report["commands"])

	def test_each_command_says_what_breaks_without_it(self):
		"""A missing binary is only actionable if you know what it cost you."""
		for name, info in self.install.check_prerequisites()["commands"].items():
			self.assertTrue(info["purpose"], f"{name} has no stated purpose")

	def test_a_missing_command_becomes_a_problem(self):
		with mock.patch.object(self.install.shutil, "which", return_value=None):
			report = self.install.check_prerequisites()
		self.assertFalse(report["ok"])
		self.assertTrue(any("git not found" in p for p in report["problems"]))

	def test_no_readable_log_names_the_group_fix(self):
		"""The remedy on Debian and Ubuntu is one usermod, so it belongs here."""
		with (
			mock.patch.object(self.install, "_journal_readable", return_value=False),
			mock.patch.object(self.install.os, "access", return_value=False),
		):
			report = self.install.check_prerequisites()
		joined = " ".join(report["problems"])
		self.assertIn("adm", joined)
		self.assertIn("usermod", joined)

	def test_journal_probe_requires_seeing_another_user(self):
		"""journalctl succeeding proves nothing on its own.

		Without the right group it returns only this user's records, so every
		sshd and sudo event is simply absent — a silence that reads as a quiet
		server rather than a broken one.
		"""
		completed = mock.Mock(returncode=0, stdout="")
		with (
			mock.patch.object(self.install.shutil, "which", return_value="/usr/bin/journalctl"),
			mock.patch.object(self.install.subprocess, "run", return_value=completed),
		):
			self.assertFalse(self.install._journal_readable(), "empty output must not count as readable")

		completed.stdout = '{"MESSAGE":"x","_UID":"0"}'
		with (
			mock.patch.object(self.install.shutil, "which", return_value="/usr/bin/journalctl"),
			mock.patch.object(self.install.subprocess, "run", return_value=completed),
		):
			self.assertTrue(self.install._journal_readable())

	def test_check_never_raises(self):
		"""It runs during install; throwing there would abort the installation."""
		with mock.patch.object(self.install.subprocess, "run", side_effect=OSError("boom")):
			self.install.check_prerequisites()


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestNoThirdPartyPythonDependencies(unittest.TestCase):
	def test_pyproject_declares_no_runtime_dependencies(self):
		"""Kept empty on purpose — see the comment in pyproject.toml.

		Everything is stdlib plus frappe, so a `bench get-app` can never fail
		here for a package that will not build on the target machine.
		"""
		import os
		import tomllib

		# get_app_path returns .../apps/server/server, so one dirname reaches
		# the repository root where pyproject.toml lives.
		root = os.path.dirname(frappe.get_app_path("server"))
		with open(os.path.join(root, "pyproject.toml"), "rb") as fh:
			data = tomllib.load(fh)
		self.assertEqual(data["project"]["dependencies"], [])
