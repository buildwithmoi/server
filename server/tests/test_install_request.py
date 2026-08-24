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


TEST_PROFILE = "__test_profile"


def _ensure_profile():
	"""A throwaway profile, so these never depend on the operator's real ones."""
	if not frappe.db.exists("GitHub Profile", TEST_PROFILE):
		frappe.get_doc(
			{
				"doctype": "GitHub Profile",
				"profile_name": TEST_PROFILE,
				"account": "Carbonite-Solutions-Ltd",
				"account_type": "Organisation",
			}
		).insert(ignore_permissions=True)
	return TEST_PROFILE


def _request(**overrides):
	base = {
		"doctype": "App Install Request",
		"operation": "Clone",
		"bench": "fb-16-server",
		"source_type": "GitHub Profile",
		"github_profile": _ensure_profile(),
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

	def test_profile_and_repo_build_an_ssh_url(self):
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

		profile = frappe.get_doc("GitHub Profile", _ensure_profile())
		profile.ssh_host_alias = "github-nonexistent-alias"
		profile.save(ignore_permissions=True)

		doc = _request()
		host = doc.resolve_git_url().split("@", 1)[1].split(":", 1)[0]
		configured = doctor.read_ssh_config().get("hosts") or []
		self.assertNotIn("github-nonexistent-alias", configured, "precondition")
		self.assertEqual(host, "github.com", "an undefined alias must fall back, not be emitted")

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

	def test_missing_profile_is_refused(self):
		with self.assertRaises(frappe.ValidationError):
			_request(github_profile=None).validate()

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
class TestPullOperation(unittest.TestCase):
	def setUp(self):
		if not frappe.db.exists("Server Bench", "fb-16-server"):
			self.skipTest("no bench discovered yet")
		self.addCleanup(frappe.db.rollback)

	def test_pull_requires_an_app_that_is_actually_in_the_bench(self):
		"""Pull updates something already there; Clone brings it in.

		Refusing here beats letting `git pull` fail inside a directory that does
		not exist, which reports a path error rather than the real mistake.
		"""
		with self.assertRaises(frappe.ValidationError) as ctx:
			_request(operation="Pull", app_name="not-installed-here", repo=None).validate()
		self.assertIn("Clone", str(ctx.exception), "the message should point at the right operation")

	def test_pull_accepts_an_installed_app(self):
		doc = _request(operation="Pull", app_name="frappe", repo=None, branch=None)
		doc.validate()
		self.assertTrue(doc.is_pull())
		self.assertEqual(doc.app_name, "frappe")

	def test_pull_argv_is_ff_only_by_default(self):
		"""Without --ff-only, git invents a merge commit on divergence.

		An unattended job quietly rewriting history in someone's checkout is not
		something this should ever do; refusing and saying why is better.
		"""
		from server.bench import installer, scanner

		doc = _request(operation="Pull", app_name="frappe", repo=None, branch=None)
		doc.validate()
		app = scanner.AppInfo(app_name="frappe", remote_name="upstream", branch="version-16")
		argv = installer.build_pull_argv(doc, app)
		self.assertEqual(argv[:2], ["git", "pull"])
		self.assertIn("--ff-only", argv)
		self.assertIn("upstream", argv)

	def test_allow_merge_drops_ff_only(self):
		from server.bench import installer, scanner

		doc = _request(operation="Pull", app_name="frappe", repo=None, branch=None, allow_merge=1)
		doc.validate()
		app = scanner.AppInfo(app_name="frappe", remote_name="upstream", branch="version-16")
		self.assertNotIn("--ff-only", installer.build_pull_argv(doc, app))

	def test_pull_uses_the_remote_the_checkout_actually_has(self):
		"""bench clones with --origin upstream, so assuming origin fails on
		every app bench ever installed."""
		from server.bench import installer, scanner

		doc = _request(operation="Pull", app_name="frappe", repo=None, branch=None)
		doc.validate()
		app = scanner.AppInfo(app_name="frappe", remote_name="upstream", branch="version-16")
		self.assertIn("upstream", installer.build_pull_argv(doc, app))
		self.assertNotIn("origin", installer.build_pull_argv(doc, app))


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
