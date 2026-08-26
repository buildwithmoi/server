# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Choosing the node a bench's frappe will accept.

Frappe-free, and the fixtures are directory trees rather than mocks: what this
module does is read a filesystem nvm laid out, and a test that stubs that away
tests nothing.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from server.bench import node


def _nvm(root: str, *versions: str) -> str:
	"""Build a directory tree shaped like nvm's."""
	base = os.path.join(root, ".nvm", "versions", "node")
	for version in versions:
		bin_dir = os.path.join(base, f"v{version}", "bin")
		os.makedirs(bin_dir, exist_ok=True)
		binary = os.path.join(bin_dir, "node")
		with open(binary, "w", encoding="utf-8") as handle:
			handle.write("#!/bin/sh\n")
		os.chmod(binary, 0o755)
	return base


def _bench(root: str, engines: object) -> str:
	"""A bench directory carrying frappe's package.json."""
	path = os.path.join(root, "bench")
	app = os.path.join(path, "apps", "frappe")
	os.makedirs(app, exist_ok=True)
	with open(os.path.join(app, "package.json"), "w", encoding="utf-8") as handle:
		json.dump({"name": "frappe", "engines": engines} if engines is not None else {}, handle)
	return path


class WhatTheBenchAsksFor(unittest.TestCase):
	"""The version comes from the bench, not from a table in this file.

	`16 → 24` is true today and was `16 → 20` a year ago. Every bench ships the
	answer in frappe's own package.json.
	"""

	def test_it_reads_the_declared_engine(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(node.required_major(_bench(root, {"node": ">=24"})), 24)

	def test_every_range_shape_yields_its_floor(self):
		for declared, expected in (
			(">=24", 24),
			("^24.1.0", 24),
			("24.x", 24),
			(">=20 <25", 20),
			(">= 18.0.0", 18),
		):
			with tempfile.TemporaryDirectory() as root, self.subTest(declared=declared):
				self.assertEqual(node.required_major(_bench(root, {"node": declared})), expected)

	def test_the_version_table_is_only_the_fallback(self):
		# Used while PROVISIONING, when there is no bench yet to ask.
		self.assertEqual(node.required_major(None, "16"), 24)
		self.assertEqual(node.required_major(None, "15"), 18)

	def test_a_bench_that_declares_nothing_falls_back_rather_than_failing(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(node.required_major(_bench(root, None), "16"), 24)

	def test_a_bench_mid_clone_has_no_package_json_and_that_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertIsNone(node.required_major(os.path.join(root, "nothing-here")))

	def test_an_unknown_frappe_version_is_no_answer_rather_than_a_guess(self):
		self.assertIsNone(node.required_major(None, "99"))


class Choosing(unittest.TestCase):
	def test_the_exact_major_wins_over_the_newest_installed(self):
		# A v15 bench says `>=18`. That is a floor, not an invitation to run it
		# on 24: the bench was built and its lockfile resolved against 18, and
		# moving it forward is a change nobody asked for.
		with tempfile.TemporaryDirectory() as root:
			available = node.installed(_nvm(root, "18.20.8", "24.18.0"))
			self.assertEqual(node.select(18, available).major, 18)
			self.assertEqual(node.select(24, available).major, 24)

	def test_the_newest_patch_of_that_major(self):
		with tempfile.TemporaryDirectory() as root:
			available = node.installed(_nvm(root, "24.1.0", "24.18.0", "24.9.0"))
			self.assertEqual(node.select(24, available).version, "24.18.0")

	def test_it_goes_up_when_the_exact_major_is_absent(self):
		with tempfile.TemporaryDirectory() as root:
			available = node.installed(_nvm(root, "18.20.8", "22.11.0", "24.18.0"))
			# The LOWEST that satisfies, not the newest: closest to what was asked.
			self.assertEqual(node.select(20, available).major, 22)

	def test_it_never_goes_down(self):
		with tempfile.TemporaryDirectory() as root:
			available = node.installed(_nvm(root, "18.20.8"))
			self.assertIsNone(node.select(24, available))

	def test_a_directory_without_a_node_binary_is_not_an_installation(self):
		with tempfile.TemporaryDirectory() as root:
			base = _nvm(root, "24.18.0")
			os.makedirs(os.path.join(base, "v22.0.0", "bin"))
			self.assertEqual([r.version for r in node.installed(base)], ["24.18.0"])

	def test_no_nvm_at_all_is_an_empty_list_not_a_crash(self):
		self.assertEqual(node.installed("/nowhere/at/all"), [])


class Activating(unittest.TestCase):
	"""What `nvm use` does, done directly.

	`nvm` is a shell function, and the worker has no shell to source it in. The
	one thing it does that matters here is put a version's bin at the front of
	PATH, so that is what this asserts.
	"""

	def _env(self, root: str, *versions: str) -> tuple[dict, str]:
		base = _nvm(root, *versions)
		env = {
			"NVM_DIR": os.path.join(root, ".nvm"),
			"PATH": os.pathsep.join([os.path.join(base, f"v{versions[0]}", "bin"), "/usr/bin", "/bin"]),
		}
		return env, base

	def test_the_wanted_version_ends_up_first(self):
		with tempfile.TemporaryDirectory() as root:
			env, base = self._env(root, "18.20.8", "24.18.0")
			updated, choice = node.activate(env, 24)
			self.assertEqual(updated["PATH"].split(os.pathsep)[0], os.path.join(base, "v24.18.0", "bin"))
			self.assertTrue(choice.changed)
			self.assertIn("v24.18.0", choice.note)
			# The note names what it was, because that is the fact that explains
			# the failure the operator was about to have.
			self.assertIn("v18.20.8", choice.note)

	def test_the_version_it_replaced_is_removed_from_path_entirely(self):
		# Prepending alone is enough for `node`, but a stale entry left behind
		# means anything walking PATH for a sibling binary still finds the old one.
		with tempfile.TemporaryDirectory() as root:
			env, base = self._env(root, "18.20.8", "24.18.0")
			updated, _ = node.activate(env, 24)
			self.assertNotIn(os.path.join(base, "v18.20.8", "bin"), updated["PATH"].split(os.pathsep))
			self.assertIn("/usr/bin", updated["PATH"].split(os.pathsep))

	def test_nothing_is_said_when_the_right_one_is_already_in_front(self):
		with tempfile.TemporaryDirectory() as root:
			env, _ = self._env(root, "24.18.0")
			_, choice = node.activate(env, 24)
			self.assertEqual(choice.note, "")
			self.assertFalse(choice.changed)

	def test_an_unsatisfiable_requirement_reports_the_command_that_fixes_it(self):
		with tempfile.TemporaryDirectory() as root:
			env, _ = self._env(root, "18.20.8")
			updated, choice = node.activate(env, 24)
			self.assertFalse(choice.satisfied)
			self.assertIn("nvm install 24", choice.note)
			# And it does NOT quietly substitute the wrong one.
			self.assertEqual(updated["PATH"], env["PATH"])

	def test_a_satisfying_node_outside_nvm_is_left_alone(self):
		# apt, or one built by hand. This app runs on machines whose toolchain
		# it did not install; refusing on those would be inventing a failure.
		with tempfile.TemporaryDirectory() as root:
			outside = os.path.join(root, "usr", "bin")
			os.makedirs(outside)
			binary = os.path.join(outside, "node")
			with open(binary, "w", encoding="utf-8") as handle:
				handle.write("#!/bin/sh\necho v24.9.0\n")
			os.chmod(binary, 0o755)
			env = {"NVM_DIR": os.path.join(root, ".nvm"), "PATH": outside}
			_, choice = node.activate(env, 24)
			self.assertTrue(choice.satisfied)
			self.assertEqual(choice.note, "")

	def test_npm_config_prefix_is_dropped(self):
		# nvm itself refuses to run while it is set: it redirects global
		# installs outside the version directory.
		with tempfile.TemporaryDirectory() as root:
			env, _ = self._env(root, "18.20.8", "24.18.0")
			env["npm_config_prefix"] = "/opt/npm"
			updated, _ = node.activate(env, 24)
			self.assertNotIn("npm_config_prefix", updated)

	def test_no_requirement_changes_nothing(self):
		with tempfile.TemporaryDirectory() as root:
			env, _ = self._env(root, "18.20.8")
			updated, choice = node.activate(env, None)
			self.assertEqual(updated, env)
			self.assertTrue(choice.satisfied)


class ThisMachine(unittest.TestCase):
	"""The case that prompted it, asserted against the real box."""

	def test_v16_wants_24_and_the_shell_default_is_18(self):
		bench = "/home/patoo/fb-16-server"
		if not os.path.isdir(os.path.join(bench, "apps", "frappe")):
			self.skipTest("not on the development box")
		self.assertEqual(node.required_major(bench), 24)


if __name__ == "__main__":
	unittest.main()
