# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Does this app actually install and run?

Everything here is a string in a config file that names code somewhere else —
a scheduler entry, a patch, a doctype controller, a log-clearing target. Python
never checks any of it, and frappe only finds out at the moment it tries to
call the thing. A hook pointing at a function that was renamed is a scheduled
job that fails silently every five minutes on a production server, and nothing
in a normal test run would notice.

The endpoint guard test is the one that matters most: this app spawns
subprocesses as the bench user, and a whitelisted method that forgets
`_assert_server_admin()` is a hole rather than a bug. One already existed — the
repository probe ran `git` for anyone, with the app's own kill switch off.
"""

from __future__ import annotations

import importlib
import inspect
import json
import pathlib
import unittest

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False

APP = pathlib.Path(__file__).resolve().parents[2]
MODULE = APP / "server"


def _resolve(dotted: str):
	module_name, _, attribute = dotted.rpartition(".")
	return getattr(importlib.import_module(module_name), attribute)


@unittest.skipUnless(frappe is not None, "requires frappe on the path")
class TestHooksResolve(unittest.TestCase):
	def setUp(self):
		from server import hooks

		self.hooks = hooks

	def test_every_scheduled_job_names_a_real_callable(self):
		"""A renamed function here fails every tick, in silence, in production."""
		events = self.hooks.scheduler_events
		dotted_paths = [d for methods in (events.get("cron") or {}).values() for d in methods]
		for key in ("all", "hourly", "daily", "weekly", "monthly"):
			dotted_paths += list(events.get(key) or [])

		self.assertTrue(dotted_paths, "no scheduled jobs are registered at all")
		for dotted in dotted_paths:
			with self.subTest(job=dotted):
				self.assertTrue(callable(_resolve(dotted)))

	def test_lifecycle_hooks_resolve(self):
		for attribute in ("after_install", "before_install", "after_migrate", "boot_session"):
			dotted = getattr(self.hooks, attribute, None)
			if isinstance(dotted, str):
				with self.subTest(hook=attribute):
					self.assertTrue(callable(_resolve(dotted)))

	def test_alerts_are_declared_self_notifying(self):
		"""Frappe drops a notification whose recipient is also its sender.

		Without this hook every alert this app raises is silently discarded on
		a server whose only System Manager is Administrator — which is what a
		fresh install is.
		"""
		self.assertIn("Alert", getattr(self.hooks, "notification_self_notify_types", []))


@unittest.skipUnless(frappe is not None, "requires frappe on the path")
class TestPatchesResolve(unittest.TestCase):
	def test_every_patch_imports_and_has_execute(self):
		patches = MODULE / "patches.txt"
		if not patches.exists():
			self.skipTest("no patches.txt")

		listed = [
			line.strip()
			for line in patches.read_text().splitlines()
			if line.strip() and not line.strip().startswith(("#", "["))
		]
		for dotted in listed:
			with self.subTest(patch=dotted):
				self.assertTrue(callable(_resolve(f"{dotted}.execute")))


@unittest.skipUnless(frappe is not None, "requires frappe on the path")
class TestDocTypesLoad(unittest.TestCase):
	def _definitions(self):
		for path in (MODULE / "server" / "doctype").rglob("*.json"):
			if path.name == f"{path.parent.name}.json":
				yield path

	def test_every_definition_is_valid_json(self):
		found = 0
		for path in self._definitions():
			found += 1
			with self.subTest(doctype=path.parent.name):
				json.loads(path.read_text())
		self.assertGreater(found, 0, "no doctype definitions found")

	def test_every_controller_imports(self):
		for path in self._definitions():
			controller = path.with_suffix(".py")
			if not controller.exists():
				continue
			dotted = str(controller.with_suffix("")).split("apps/server/")[-1].replace("/", ".")
			with self.subTest(controller=dotted):
				importlib.import_module(dotted)

	def test_select_fields_declare_options(self):
		"""A Select with no options renders as an empty dropdown."""
		for path in self._definitions():
			definition = json.loads(path.read_text())
			for field in definition.get("fields", []):
				if field.get("fieldtype") == "Select" and not field.get("options"):
					self.fail(f"{path.parent.name}.{field['fieldname']} is a Select with no options")

	def test_every_field_is_in_the_field_order(self):
		"""A field missing from field_order is invisible on the form."""
		for path in self._definitions():
			definition = json.loads(path.read_text())
			order = definition.get("field_order")
			if not order:
				continue
			declared = {f["fieldname"] for f in definition.get("fields", [])}
			missing = declared - set(order)
			with self.subTest(doctype=path.parent.name):
				self.assertFalse(missing, f"{path.parent.name}: {sorted(missing)} not in field_order")


@unittest.skipUnless(frappe is not None, "requires frappe on the path")
class TestEndpointsAreGuarded(unittest.TestCase):
	"""Every whitelisted method must check the caller.

	This app runs commands as the bench user. A whitelisted method that skips
	the guard is not a bug, it is a hole — and one already existed: the
	repository probe shelled out to git for any authenticated user, with the
	app's own kill switch turned off.
	"""

	def test_no_whitelisted_endpoint_skips_the_admin_check(self):
		from server import api

		unguarded = []
		for name, value in vars(api).items():
			if name.startswith("_") or not callable(value):
				continue
			try:
				source = inspect.getsource(value)
			except (OSError, TypeError):
				continue
			if "@frappe.whitelist" in source and "_assert_server_admin()" not in source:
				unguarded.append(name)

		self.assertEqual(unguarded, [], f"whitelisted without a permission check: {unguarded}")

	def test_mutating_endpoints_are_post_only(self):
		"""A GET carries the session cookie with no CSRF token.

		run_ssl and run_restore were both reachable by GET, so a link could
		queue a privileged job — one of which stops nginx.
		"""
		from server import api

		must_post = (
			"run_ssl",
			"run_restore",
			"run_bench_command",
			"prune_backups",
			"update_site_config",
			"cancel_install_request",
			"mark_alerts_read",
		)
		for name in must_post:
			endpoint = getattr(api, name, None)
			if endpoint is None:
				continue
			with self.subTest(endpoint=name):
				self.assertIn('methods=["POST"]', inspect.getsource(endpoint))


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestLogClearingTargets(unittest.TestCase):
	def test_named_doctypes_exist(self):
		from server import hooks

		for doctype in getattr(hooks, "default_log_clearing_doctypes", {}) or {}:
			with self.subTest(doctype=doctype):
				self.assertTrue(frappe.db.exists("DocType", doctype))


if __name__ == "__main__":
	unittest.main()
