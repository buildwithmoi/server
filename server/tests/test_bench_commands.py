# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Bench command catalogue.

"Run any bench command" is a remote shell with extra steps, so every argv is
assembled from a fixed catalogue entry plus parameters matched against a
pattern. These guard that property, and the risk metadata the interface relies
on to decide how much friction to put in front of a command.
"""

from __future__ import annotations

import unittest

from server.bench import commands


class TestCatalogue(unittest.TestCase):
	def test_ids_are_unique(self):
		ids = [c.id for c in commands.ALL_COMMANDS]
		self.assertEqual(len(ids), len(set(ids)))

	def test_every_command_explains_itself(self):
		for c in commands.ALL_COMMANDS:
			self.assertTrue(c.label, f"{c.id} has no label")
			self.assertTrue(c.description, f"{c.id} has no description")
			self.assertIn(c.scope, (commands.SCOPE_BENCH, commands.SCOPE_SITE))
			self.assertIn(
				c.risk,
				(
					commands.RISK_READ,
					commands.RISK_ROUTINE,
					commands.RISK_DESTRUCTIVE,
					commands.RISK_UNSUPPORTED,
				),
			)

	def test_unsupported_commands_say_why(self):
		"""They are listed on purpose, so searching for `console` finds it.

		Listing something with no explanation would be worse than hiding it.
		"""
		for c in commands.ALL_COMMANDS:
			if c.risk == commands.RISK_UNSUPPORTED:
				self.assertTrue(c.unsupported_reason, f"{c.id} is unsupported but gives no reason")
				self.assertFalse(c.runnable)

	def test_interactive_commands_are_never_runnable(self):
		"""A worker has closed stdin; these would abort the moment they prompt."""
		for cid in ("site.console", "site.mariadb", "bench.new-app"):
			self.assertFalse(commands.get(cid).runnable, f"{cid} must not be runnable")

	def test_long_running_servers_are_not_runnable(self):
		self.assertFalse(commands.get("bench.start").runnable)

	def test_destructive_ones_are_marked(self):
		for cid in ("site.uninstall-app", "bench.update", "bench.remove-app"):
			self.assertEqual(commands.get(cid).risk, commands.RISK_DESTRUCTIVE, cid)

	def test_drop_site_is_not_offered_from_here(self):
		"""It was catalogued as destructive-but-runnable and could never run.

		frappe's drop-site takes the site as a POSITIONAL argument, not the
		global --site option this catalogue builds, so click refused the command
		with "Missing argument SITE" — the operator typed the full label into
		the confirmation box and watched it fail. It also needs the database
		root password on the command line, which this catalogue has no way to
		redact out of the stored command the way the restore path does.
		"""
		command = commands.get("site.drop-site")
		self.assertEqual(command.risk, commands.RISK_UNSUPPORTED)
		self.assertFalse(command.runnable)
		self.assertIn("positional", command.unsupported_reason)
		with self.assertRaises(commands.CommandRefused):
			commands.build_argv(command, "/usr/local/bin/bench", "a.site")


class TestArgvConstruction(unittest.TestCase):
	BENCH = "/usr/local/bin/bench"

	def test_site_scope_inserts_the_site(self):
		argv = commands.build_argv(commands.get("site.migrate"), self.BENCH, "a.site")
		self.assertEqual(argv, [self.BENCH, "--site", "a.site", "migrate"])

	def test_bench_scope_has_no_site(self):
		argv = commands.build_argv(commands.get("bench.restart"), self.BENCH)
		self.assertEqual(argv, [self.BENCH, "restart"])
		self.assertNotIn("--site", argv)

	def test_site_scope_without_a_site_is_refused(self):
		with self.assertRaises(commands.CommandRefused):
			commands.build_argv(commands.get("site.migrate"), self.BENCH)

	def test_unsupported_is_refused_at_build_time(self):
		"""Defence in depth: the API refuses too, but the builder is the last gate."""
		with self.assertRaises(commands.CommandRefused):
			commands.build_argv(commands.get("site.console"), self.BENCH, "a.site")

	def test_parameters_are_appended(self):
		argv = commands.build_argv(commands.get("site.install-app"), self.BENCH, "a.site", {"app": "erpnext"})
		self.assertEqual(argv[-1], "erpnext")

	def test_a_missing_required_parameter_is_refused(self):
		with self.assertRaises(commands.CommandRefused):
			commands.build_argv(commands.get("site.install-app"), self.BENCH, "a.site", {})

	def test_parameters_are_pattern_checked(self):
		"""shell=False already makes injection impossible; this stops nonsense
		becoming a confusing subprocess failure a minute later."""
		for bad in ("erp next", "../../etc", "erpnext; rm -rf /", "-rf", ""):
			with self.subTest(value=bad), self.assertRaises(commands.CommandRefused):
				commands.build_argv(commands.get("site.install-app"), self.BENCH, "a.site", {"app": bad})

	def test_branch_parameter_allows_slashes_but_not_spaces(self):
		argv = commands.build_argv(
			commands.get("bench.switch-to-branch"), self.BENCH, None, {"branch": "feat/thing"}
		)
		self.assertEqual(argv[-1], "feat/thing")
		with self.assertRaises(commands.CommandRefused):
			commands.build_argv(commands.get("bench.switch-to-branch"), self.BENCH, None, {"branch": "a b"})

	def test_nothing_from_a_caller_reaches_argv_unchecked(self):
		"""Every appended element must come from the entry or a checked param."""
		entry = commands.get("site.install-app")
		argv = commands.build_argv(entry, self.BENCH, "a.site", {"app": "erpnext", "extra": "--force"})
		self.assertNotIn("--force", argv, "an unknown parameter must be ignored, not appended")


class TestSerialisation(unittest.TestCase):
	def test_picker_payload_carries_what_the_ui_needs(self):
		rows = commands.as_dicts()
		self.assertEqual(len(rows), len(commands.ALL_COMMANDS))
		for row in rows:
			for key in ("id", "label", "scope", "description", "risk", "runnable", "preview", "params"):
				self.assertIn(key, row)

	def test_preview_shows_the_site_placeholder_only_for_site_scope(self):
		by_id = {r["id"]: r for r in commands.as_dicts()}
		self.assertIn("--site <site>", by_id["site.migrate"]["preview"])
		self.assertNotIn("--site", by_id["bench.restart"]["preview"])


if __name__ == "__main__":
	unittest.main()
