# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""App Install Request validation and pre-flight tests.

Needs a site, so it runs under `bench run-tests` and skips otherwise.
"""

from __future__ import annotations

import unittest

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False


def _request(**overrides):
	base = {
		"doctype": "App Install Request",
		"bench": "fb-16-server",
		"source_type": "GitHub Org + Repo",
		"github_org": "Carbonite-Solutions-Ltd",
		"repo": "server",
		"branch": "version-16",
		"skip_assets": 1,
	}
	base.update(overrides)
	return frappe.get_doc(base)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestUrlResolution(unittest.TestCase):
	def setUp(self):
		if not frappe.db.exists("Server Bench", "fb-16-server"):
			self.skipTest("no bench discovered yet")
		self.addCleanup(frappe.db.rollback)

	def test_org_and_repo_build_an_ssh_url(self):
		doc = _request()
		doc.validate()
		self.assertTrue(doc.resolved_git_url.startswith("git@"))
		self.assertTrue(doc.resolved_git_url.endswith(":Carbonite-Solutions-Ltd/server.git"))
		self.assertEqual(doc.app_name, "server")

	def test_alias_is_only_used_when_ssh_config_defines_it(self):
		"""An alias that is not in ~/.ssh/config produces 'could not resolve host'.

		That is a worse, more confusing failure than the ambiguous-identity
		problem the alias was meant to fix, so the alias is an upgrade when
		present and plain github.com otherwise.
		"""
		from server.bench import doctor

		configured = doctor.read_ssh_config().get("hosts") or []
		host = _request().resolve_git_url().split("@", 1)[1].split(":", 1)[0]
		if "github-carbonite" in configured:
			self.assertEqual(host, "github-carbonite")
		else:
			self.assertEqual(host, "github.com")

	def test_app_name_from_https_url(self):
		doc = _request(source_type="Git URL", git_url="https://github.com/frappe/hrms.git", repo=None)
		doc.validate()
		self.assertEqual(doc.app_name, "hrms")

	def test_app_name_from_ssh_url(self):
		doc = _request(source_type="Git URL", git_url="git@github.com:org/my_app.git", repo=None)
		doc.validate()
		self.assertEqual(doc.app_name, "my_app")


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestValidationRefusals(unittest.TestCase):
	def setUp(self):
		if not frappe.db.exists("Server Bench", "fb-16-server"):
			self.skipTest("no bench discovered yet")
		self.addCleanup(frappe.db.rollback)

	def test_full_url_in_the_repo_field_is_refused(self):
		"""Pasting a URL where a name belongs is the most likely user error."""
		with self.assertRaises(frappe.ValidationError):
			_request(repo="git@github.com:x/y.git").validate()

	def test_shell_metacharacters_in_branch_are_refused(self):
		"""shell=False already makes this inert; refusing keeps typos cheap."""
		with self.assertRaises(frappe.ValidationError):
			_request(branch="main; rm -rf /").validate()

	def test_path_traversal_in_site_is_refused(self):
		with self.assertRaises(frappe.ValidationError):
			_request(install_on_site="../../etc").validate()

	def test_non_git_remote_is_refused(self):
		with self.assertRaises(frappe.ValidationError):
			_request(source_type="Git URL", git_url="file:///etc/passwd", repo=None).validate()

	def test_valid_input_passes(self):
		_request().validate()


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestArgvConstruction(unittest.TestCase):
	def setUp(self):
		if not frappe.db.exists("Server Bench", "fb-16-server"):
			self.skipTest("no bench discovered yet")
		self.addCleanup(frappe.db.rollback)
		from server.server.doctype.server_settings.server_settings import get_settings

		self.settings = get_settings()

	def test_app_name_is_passed_positionally(self):
		"""bench infers the name from the URL, and gets it wrong behind an alias."""
		from server.bench.installer import build_get_app_argv

		doc = _request()
		doc.validate()
		argv = build_get_app_argv(doc, self.settings)
		self.assertEqual(argv[1], "get-app")
		self.assertEqual(argv[2], "server", "app name must precede the URL")
		self.assertEqual(argv[3], doc.resolved_git_url)

	def test_resolve_deps_is_never_passed(self):
		"""It fetches hooks.py over GitHub's HTTP API and silently returns
		nothing for a private repository, so it resolves to no dependencies."""
		from server.bench.installer import build_get_app_argv

		doc = _request(overwrite_existing=1, install_on_site="local.16.server")
		doc.validate()
		self.assertNotIn("--resolve-deps", build_get_app_argv(doc, self.settings))

	def test_flags_are_included_when_set(self):
		from server.bench.installer import build_get_app_argv, build_install_app_argv

		doc = _request(overwrite_existing=1, install_on_site="local.16.server", force_install=1)
		doc.validate()
		argv = build_get_app_argv(doc, self.settings)
		self.assertIn("--skip-assets", argv)
		self.assertIn("--overwrite", argv)
		self.assertIn("--branch", argv)

		install = build_install_app_argv(doc, self.settings)
		self.assertEqual(install[1:4], ["--site", "local.16.server", "install-app"])
		self.assertIn("--force", install)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestInterlock(unittest.TestCase):
	def test_installs_are_blocked_while_the_switch_is_off(self):
		"""Nothing in this app shells out to bench until this is deliberately armed."""
		from server.server.doctype.server_settings.server_settings import get_settings

		settings = get_settings()
		previous = settings.allow_app_install
		settings.db_set("allow_app_install", 0)
		self.addCleanup(lambda: settings.db_set("allow_app_install", previous))

		with self.assertRaises(frappe.PermissionError):
			get_settings().assert_installs_allowed()


if __name__ == "__main__":
	unittest.main()
