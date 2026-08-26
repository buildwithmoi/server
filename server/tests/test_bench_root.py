# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Where the bench scan looks, and how it says so.

The bug these exist for: the DocType shipped `default: "/home/patoo"` — the
home directory of the machine it was written on. A default on a Data field is
applied the first time the Single is saved, so every install wrote that path
into its own settings, and the scan then searched a directory that did not
exist. The first server it was installed on showed an empty page while holding
twelve benches, and nothing on that page named the directory it had searched.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from server.bench import scanner


def _bench(root: str, name: str, *, missing: tuple[str, ...] = ()) -> str:
	path = os.path.join(root, name)
	for marker in scanner.BENCH_MARKERS:
		if marker in missing:
			continue
		os.makedirs(os.path.join(path, marker), exist_ok=True)
	return path


class NoDefaultRootIsShipped(unittest.TestCase):
	"""The regression itself, asserted against the JSON that ships."""

	def test_bench_root_has_no_default(self):
		here = pathlib.Path(__file__).resolve().parents[1]
		schema = json.loads(
			(here / "server" / "doctype" / "server_settings" / "server_settings.json").read_text()
		)
		field = next(f for f in schema["fields"] if f["fieldname"] == "bench_root")
		self.assertIsNone(
			field.get("default"),
			"Bench Root must have no default. A fixed one is one machine's home "
			"directory shipped to every server; the fallback is computed from "
			"where this bench actually is.",
		)

	def test_no_field_defaults_to_a_home_directory(self):
		# The general form of the same mistake. /var and /usr paths are real
		# platform defaults; /home/<someone> is a development box.
		here = pathlib.Path(__file__).resolve().parents[1] / "server" / "doctype"
		offenders = []
		for schema_file in here.glob("*/*.json"):
			schema = json.loads(schema_file.read_text())
			for field in schema.get("fields", []):
				value = field.get("default")
				if isinstance(value, str) and value.startswith(("/home/", "/root/", "/Users/")):
					offenders.append(f"{schema_file.name}:{field['fieldname']} = {value}")
		self.assertEqual(offenders, [], f"machine-specific defaults: {offenders}")

	def test_no_module_falls_back_to_a_hardcoded_bench(self):
		root = pathlib.Path(__file__).resolve().parents[1]
		offenders = []
		for source in root.rglob("*.py"):
			if "tests" in source.parts or "patches" in source.parts:
				continue
			for number, line in enumerate(source.read_text().splitlines(), 1):
				if line.lstrip().startswith("#"):
					continue
				if "/home/patoo" in line:
					offenders.append(f"{source.name}:{number}")
		self.assertEqual(offenders, [], f"hardcoded developer paths: {offenders}")


class Diagnosing(unittest.TestCase):
	"""What the empty page has to be able to say."""

	def test_a_root_full_of_benches_reports_them(self):
		with tempfile.TemporaryDirectory() as root:
			_bench(root, "frappe-bench-hz1")
			_bench(root, "frappe-bench-hz2")
			report = scanner.diagnose(root)
			self.assertEqual(report["benches"], 2)
			self.assertTrue(all(c["is_bench"] for c in report["candidates"]))

	def test_a_root_that_does_not_exist_says_so(self):
		# The exact failure: this is what "no benches found" was hiding.
		report = scanner.diagnose("/home/nobody-lives-here")
		self.assertFalse(report["exists"])
		self.assertEqual(report["benches"], 0)
		self.assertEqual(report["candidates"], [])

	def test_a_near_miss_names_what_it_lacks(self):
		with tempfile.TemporaryDirectory() as root:
			_bench(root, "frappe-bench-copied", missing=("config/pids",))
			report = scanner.diagnose(root)
			self.assertEqual(report["benches"], 0)
			self.assertEqual(report["candidates"][0]["missing"], ["config/pids"])
			self.assertIn("config/pids", report["candidates"][0]["reason"])

	def test_unrelated_directories_are_not_listed(self):
		# Somebody's Documents folder is not a broken bench, and listing it
		# would bury the near-miss that matters.
		with tempfile.TemporaryDirectory() as root:
			_bench(root, "frappe-bench-hz1", missing=("logs",))
			os.makedirs(os.path.join(root, "Documents", "whatever"))
			report = scanner.diagnose(root)
			self.assertEqual([c["name"] for c in report["candidates"]], ["frappe-bench-hz1"])

	def test_hidden_directories_are_skipped(self):
		with tempfile.TemporaryDirectory() as root:
			_bench(root, ".cache")
			self.assertEqual(scanner.diagnose(root)["candidates"], [])

	def test_it_agrees_with_the_scan_it_explains(self):
		# A diagnosis that disagreed with find_benches would be worse than none.
		with tempfile.TemporaryDirectory() as root:
			_bench(root, "one")
			_bench(root, "two", missing=("sites",))
			report = scanner.diagnose(root)
			self.assertEqual(
				sorted(c["path"] for c in report["candidates"] if c["is_bench"]),
				sorted(scanner.find_benches(root)),
			)


if __name__ == "__main__":
	unittest.main()


class TheScanIsScheduled(unittest.TestCase):
	"""It existed and was never wired up.

	`discovery.enqueue_scan` was written as "the scheduler entry point" and
	then not listed in any scheduler slot, so the bench table was only ever
	filled by somebody pressing Rescan. A fresh install therefore showed an
	empty Benches page on a machine holding twelve of them.
	"""

	def test_the_bench_scan_runs_on_the_scheduler(self):
		from server import hooks

		scheduled = set()
		for slot in hooks.scheduler_events.values():
			if isinstance(slot, dict):
				for methods in slot.values():
					scheduled.update(methods)
			else:
				scheduled.update(slot)

		self.assertIn("server.bench.discovery.enqueue_scan", scheduled)

	def test_installing_the_app_fills_the_bench_table(self):
		import inspect

		from server import install

		source = inspect.getsource(install.after_install)
		self.assertIn("_scan_benches", source)
