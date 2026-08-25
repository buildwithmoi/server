# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Machine statistics tests.

These read the real /proc and the real disk, because that is the thing being
tested: a parser for a file format that this machine actually has. What is
asserted is shape and invariants, never specific values — a test that expects
58% memory fails tomorrow for no reason.

The contract that matters most is that nothing here raises. A statistics panel
must not be able to take a page down.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from server import system


class TestHuman(unittest.TestCase):
	def test_scales_through_the_units(self):
		self.assertEqual(system.human(512), "512 B")
		self.assertEqual(system.human(1536), "1.5 KB")
		self.assertEqual(system.human(1024**3 * 2), "2.0 GB")

	def test_very_large_values_stop_at_terabytes(self):
		self.assertTrue(system.human(1024**5).endswith("TB"))

	def test_zero_is_not_an_error(self):
		self.assertEqual(system.human(0), "0 B")


class TestLevels(unittest.TestCase):
	def test_thresholds_are_inclusive_at_the_boundary(self):
		self.assertEqual(system._level(79.9, 80, 90), "ok")
		self.assertEqual(system._level(80.0, 80, 90), "warn")
		self.assertEqual(system._level(90.0, 80, 90), "critical")


class TestDisk(unittest.TestCase):
	def test_reads_a_real_filesystem(self):
		reading = system.disk("/")
		self.assertIsNotNone(reading)
		self.assertGreater(reading.total, 0)
		self.assertLessEqual(reading.used, reading.total)
		self.assertIn(reading.level, ("ok", "warn", "critical"))

	def test_a_missing_path_returns_none_rather_than_raising(self):
		self.assertIsNone(system.disk("/nonexistent-path-for-tests"))

	def test_one_reading_per_filesystem_not_per_path(self):
		"""Benches usually share a disk; the same 90% nine times is noise."""
		with tempfile.TemporaryDirectory() as root:
			a = os.path.join(root, "a")
			b = os.path.join(root, "b")
			os.makedirs(a)
			os.makedirs(b)
			readings = system.mounts_for([a, b])
			devices = {os.stat(r.label).st_dev for r in readings}
			self.assertEqual(len(readings), len(devices))

	def test_paths_that_do_not_exist_are_skipped(self):
		readings = system.mounts_for(["/nonexistent-path-for-tests"])
		self.assertTrue(all(os.path.isdir(r.label) for r in readings))


class TestMemory(unittest.TestCase):
	#: A machine with plenty of memory available and almost none "free",
	#: because the page cache is holding the rest. This is what a busy,
	#: perfectly healthy server looks like, and the whole point of preferring
	#: MemAvailable is that MemFree would call it 97% used.
	BUSY_BUT_HEALTHY = {
		"MemTotal": 8_000_000_000,
		"MemFree": 200_000_000,
		"MemAvailable": 6_000_000_000,
	}

	def test_uses_available_rather_than_free(self):
		"""MemFree excludes the page cache, which Linux hands back on demand.

		Reporting it as used makes a healthy machine look out of memory.

		Against a FIXED reading rather than the live one. The first version of
		this test called `_meminfo()` and then `memory()`, which reads
		/proc/meminfo a second time — on a live box the number moves between the
		two calls, and the test failed roughly one run in eight. A race in a
		test is worse than no test: it teaches whoever sees it that a red suite
		is normal.
		"""
		from unittest.mock import patch

		with patch.object(system, "_meminfo", return_value=dict(self.BUSY_BUT_HEALTHY)):
			reading = system.memory()

		self.assertEqual(reading.free, self.BUSY_BUT_HEALTHY["MemAvailable"])
		self.assertEqual(reading.used, 2_000_000_000)
		self.assertEqual(round(reading.percent), 25, "MemFree would have made this 97%")

	def test_falls_back_to_free_on_a_kernel_without_memavailable(self):
		"""Ancient kernels do not report it, and returning None would mean the
		dashboard showing no memory reading at all rather than a rougher one."""
		from unittest.mock import patch

		info = {"MemTotal": 8_000_000_000, "MemFree": 200_000_000}
		with patch.object(system, "_meminfo", return_value=info):
			reading = system.memory()

		self.assertEqual(reading.free, 200_000_000)

	def test_percentage_is_within_range(self):
		reading = system.memory()
		if reading is None:
			self.skipTest("no /proc/meminfo")
		self.assertGreaterEqual(reading.percent, 0)
		self.assertLessEqual(reading.percent, 100)


class TestLoad(unittest.TestCase):
	def test_load_is_reported_per_cpu(self):
		"""8 is idle on a 16-core box and on fire on a 2-core one."""
		reading = system.load()
		if reading is None:
			self.skipTest("no load average on this platform")
		self.assertGreaterEqual(reading["cpus"], 1)
		self.assertAlmostEqual(reading["per_cpu"], reading["one"] / reading["cpus"], places=1)


class TestBackupUsage(unittest.TestCase):
	def test_finds_and_ranks_backups_by_size(self):
		with tempfile.TemporaryDirectory() as root:
			for site, size in (("small.site", 100), ("big.site", 5000)):
				path = os.path.join(root, "sites", site, "private", "backups")
				os.makedirs(path)
				with open(os.path.join(path, "dump.sql.gz"), "wb") as handle:
					handle.write(b"x" * size)

			rows = system.backup_usage(root)
			self.assertEqual([r["site"] for r in rows], ["big.site", "small.site"])
			self.assertEqual(rows[0]["files"], 1)

	def test_a_site_with_no_backups_is_omitted(self):
		with tempfile.TemporaryDirectory() as root:
			os.makedirs(os.path.join(root, "sites", "empty.site"))
			self.assertEqual(system.backup_usage(root), [])

	def test_a_bench_without_a_sites_directory_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(system.backup_usage(root), [])


class TestSnapshot(unittest.TestCase):
	def test_returns_every_section(self):
		report = system.snapshot(["/"])
		for key in ("disks", "memory", "load", "uptime", "hostname", "worst_level"):
			self.assertIn(key, report)

	def test_worst_level_is_the_worst_of_the_disks(self):
		report = system.snapshot(["/"])
		levels = [d["level"] for d in report["disks"]]
		order = ["ok", "warn", "critical"]
		self.assertEqual(report["worst_level"], max(levels, key=order.index, default="ok"))

	def test_a_nonexistent_bench_path_does_not_break_the_snapshot(self):
		report = system.snapshot(["/nonexistent-path-for-tests"])
		self.assertTrue(report["disks"])


if __name__ == "__main__":
	unittest.main()
