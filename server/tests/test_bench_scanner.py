# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Bench discovery tests.

Frappe-free, like the log parser: everything here is filesystem inspection, and
it is exercised against synthetic bench directories built in a temp dir so the
tests do not depend on this machine happening to have benches on it.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from server.bench import scanner


def make_bench(root: str, name: str, *, complete: bool = True, config: dict | None = None) -> str:
	import json

	path = os.path.join(root, name)
	markers = scanner.BENCH_MARKERS if complete else ("apps", "sites")
	for marker in markers:
		os.makedirs(os.path.join(path, marker), exist_ok=True)
	if complete:
		with open(os.path.join(path, "sites", "common_site_config.json"), "w", encoding="utf-8") as fh:
			json.dump(config or {}, fh)
	return path


class BenchTempCase(unittest.TestCase):
	def setUp(self):
		self._tmp = tempfile.TemporaryDirectory()
		self.root = self._tmp.name
		self.addCleanup(self._tmp.cleanup)


class TestBenchDetection(BenchTempCase):
	def test_all_five_markers_are_required(self):
		"""Matching bench's own definition matters — a partial tree is not a bench.

		config/pids is the one people forget; without it a bare apps/sites/config
		skeleton would be treated as a bench and every command against it would
		fail somewhere deep inside the CLI.
		"""
		complete = make_bench(self.root, "good")
		partial = make_bench(self.root, "partial", complete=False)
		self.assertTrue(scanner.is_bench_directory(complete))
		self.assertFalse(scanner.is_bench_directory(partial))

	def test_missing_config_pids_disqualifies(self):
		path = make_bench(self.root, "nearly")
		os.rmdir(os.path.join(path, "config", "pids"))
		self.assertFalse(scanner.is_bench_directory(path))

	def test_find_benches_returns_only_real_ones_sorted(self):
		make_bench(self.root, "b-second")
		make_bench(self.root, "a-first")
		make_bench(self.root, "not-a-bench", complete=False)
		os.makedirs(os.path.join(self.root, ".hidden"))

		found = [os.path.basename(p) for p in scanner.find_benches(self.root)]
		self.assertEqual(found, ["a-first", "b-second"])

	def test_missing_root_is_not_an_error(self):
		self.assertEqual(scanner.find_benches(os.path.join(self.root, "nope")), [])


class TestBenchConfig(BenchTempCase):
	def test_ports_and_flags_are_read(self):
		make_bench(
			self.root,
			"fb",
			config={
				"default_site": "site.local",
				"frappe_user": "patoo",
				"shallow_clone": True,
				"webserver_port": 8008,
				"socketio_port": 9008,
				"redis_queue": "redis://127.0.0.1:11008",
				"redis_cache": "redis://127.0.0.1:13008",
			},
		)
		info = scanner.read_bench(os.path.join(self.root, "fb"))
		self.assertEqual(info.webserver_port, 8008)
		self.assertEqual(info.socketio_port, 9008)
		self.assertEqual(info.redis_queue_port, 11008)
		self.assertEqual(info.redis_cache_port, 13008)
		self.assertEqual(info.default_site, "site.local")
		self.assertTrue(info.shallow_clone)

	def test_unparseable_config_does_not_raise(self):
		path = make_bench(self.root, "fb")
		with open(os.path.join(path, "sites", "common_site_config.json"), "w", encoding="utf-8") as fh:
			fh.write("{ not json")
		info = scanner.read_bench(path)
		self.assertIsNone(info.webserver_port)
		self.assertIsNone(info.error, "a bad config file is not a reason to call it 'not a bench'")

	def test_non_bench_path_is_reported(self):
		path = make_bench(self.root, "fb", complete=False)
		self.assertEqual(scanner.read_bench(path).error, "not a bench directory")


class TestRedisPortParsing(unittest.TestCase):
	def test_variants(self):
		cases = {
			"redis://127.0.0.1:11008": 11008,
			"redis://localhost:6379/": 6379,
			"unix:///tmp/redis.sock": None,
			"": None,
			None: None,
		}
		for value, expected in cases.items():
			with self.subTest(value=value):
				self.assertEqual(scanner._port_from_redis_url(value), expected)


class TestSites(BenchTempCase):
	def test_only_directories_with_a_site_config_count(self):
		import json

		path = make_bench(self.root, "fb", config={"default_site": "real.site"})
		for site in ("real.site", "other.site"):
			os.makedirs(os.path.join(path, "sites", site))
			with open(os.path.join(path, "sites", site, "site_config.json"), "w", encoding="utf-8") as fh:
				json.dump({"installed_apps": ["frappe", "server"]}, fh)
		# assets/ is a real directory inside sites/ and must never be read as a site.
		os.makedirs(os.path.join(path, "sites", "assets"))

		info = scanner.read_bench(path)
		names = sorted(s.site_name for s in info.sites)
		self.assertEqual(names, ["other.site", "real.site"])
		self.assertEqual([s.is_default for s in info.sites if s.site_name == "real.site"], [True])
		self.assertIn("server", next(s for s in info.sites if s.site_name == "real.site").installed_apps)


class TestApps(BenchTempCase):
	def test_apps_txt_drives_the_list(self):
		path = make_bench(self.root, "fb")
		for app in ("frappe", "server"):
			os.makedirs(os.path.join(path, "apps", app))
		os.makedirs(os.path.join(path, "apps", "leftover"))
		with open(os.path.join(path, "sites", "apps.txt"), "w", encoding="utf-8") as fh:
			fh.write("frappe\nserver\n")

		info = scanner.read_bench(path)
		self.assertEqual(
			[a.app_name for a in info.apps],
			["frappe", "server"],
			"apps.txt is the source of truth; a stray directory is not an installed app",
		)

	def test_falls_back_to_directory_listing(self):
		path = make_bench(self.root, "fb")
		for app in ("alpha", "beta"):
			os.makedirs(os.path.join(path, "apps", app))
		info = scanner.read_bench(path)
		self.assertEqual(sorted(a.app_name for a in info.apps), ["alpha", "beta"])

	def test_app_without_git_is_described_not_skipped(self):
		path = make_bench(self.root, "fb")
		os.makedirs(os.path.join(path, "apps", "handmade"))
		info = scanner.read_bench(path)
		app = next(a for a in info.apps if a.app_name == "handmade")
		self.assertIsNone(app.git_url)
		self.assertFalse(app.is_shallow)


class TestRemotePreference(unittest.TestCase):
	def test_upstream_is_tried_before_origin(self):
		"""bench clones with --origin upstream, so that is the remote that exists.

		Looking for `origin` first would report no git URL for every app bench
		installed, which is all of them.
		"""
		self.assertEqual(scanner.REMOTE_NAMES[0], "upstream")
		self.assertIn("origin", scanner.REMOTE_NAMES)


if __name__ == "__main__":
	unittest.main()
