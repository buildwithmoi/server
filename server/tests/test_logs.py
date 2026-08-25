# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Log discovery and tailing tests.

Frappe-free, against synthetic log directories. The two things worth proving
are that the tail really reads from the end — a worker.log is routinely
hundreds of megabytes — and that nothing outside the bench's log directories
can be opened, because these paths arrive from a browser.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from server.bench import logs

SITE = "erp.example.com"


def make_bench(root: str, files: dict[str, str], site_files: dict[str, str] | None = None) -> None:
	bench_logs = os.path.join(root, "logs")
	os.makedirs(bench_logs, exist_ok=True)
	for name, content in files.items():
		with open(os.path.join(bench_logs, name), "w") as handle:
			handle.write(content)

	site_logs = os.path.join(root, "sites", SITE, "logs")
	os.makedirs(site_logs, exist_ok=True)
	for name, content in (site_files or {}).items():
		with open(os.path.join(site_logs, name), "w") as handle:
			handle.write(content)


class TestListing(unittest.TestCase):
	def test_finds_bench_and_site_logs_and_labels_each(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "a\n"}, {"database.log": "b\n"})
			found = logs.list_logs(root, [SITE])
			self.assertEqual({f.scope for f in found}, {"bench", SITE})

	def test_ignores_files_that_are_not_logs(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "a\n", "notes.txt": "x", "config.json": "{}"})
			self.assertEqual({f.name for f in logs.list_logs(root, [])}, {"worker.log"})

	def test_rotations_are_included_and_marked(self):
		"""What you are looking for is often just the other side of midnight."""
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "a\n", "worker.log.1": "old\n"})
			found = {f.name: f for f in logs.list_logs(root, [])}
			self.assertFalse(found["worker.log"].is_rotation)
			self.assertTrue(found["worker.log.1"].is_rotation)

	def test_a_rotation_inherits_the_description_of_its_base(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.error.log.2": "x\n"})
			self.assertIn("raised", logs.list_logs(root, [])[0].description)

	def test_most_recently_written_first(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"old.log": "x\n", "new.log": "y\n"})
			directory = os.path.join(root, "logs")
			os.utime(os.path.join(directory, "old.log"), (1_600_000_000, 1_600_000_000))
			os.utime(os.path.join(directory, "new.log"), (1_700_000_000, 1_700_000_000))
			self.assertEqual([f.name for f in logs.list_logs(root, [])], ["new.log", "old.log"])

	def test_a_missing_log_directory_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			self.assertEqual(logs.list_logs(root, [SITE]), [])


class TestPathSafety(unittest.TestCase):
	"""These paths come from a browser, and common_site_config.json holds the
	database credentials one directory up from the logs."""

	def test_paths_outside_the_log_directories_are_refused(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "a\n"})
			roots = [d for d, _ in logs.log_directories(root, [SITE])]

			for outside in (
				"/etc/passwd",
				os.path.join(root, "sites", "common_site_config.json"),
				os.path.join(root, "logs", "..", "sites", "common_site_config.json"),
				os.path.join(root, "logs", "..", "..", "etc", "shadow"),
			):
				with self.subTest(path=outside):
					self.assertFalse(logs.is_inside(roots, outside))

	def test_a_symlink_out_of_the_log_directory_is_refused(self):
		with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as elsewhere:
			make_bench(root, {"worker.log": "a\n"})
			secret = os.path.join(elsewhere, "secret.log")
			with open(secret, "w") as handle:
				handle.write("credentials\n")
			link = os.path.join(root, "logs", "innocent.log")
			os.symlink(secret, link)

			roots = [d for d, _ in logs.log_directories(root, [SITE])]
			self.assertFalse(logs.is_inside(roots, link))

	def test_a_real_log_is_allowed(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "a\n"})
			roots = [d for d, _ in logs.log_directories(root, [SITE])]
			self.assertTrue(logs.is_inside(roots, os.path.join(root, "logs", "worker.log")))


class TestTail(unittest.TestCase):
	def _write(self, root: str, count: int) -> str:
		make_bench(root, {"worker.log": "".join(f"line {i}\n" for i in range(count))})
		return os.path.join(root, "logs", "worker.log")

	def test_returns_the_last_lines_not_the_first(self):
		with tempfile.TemporaryDirectory() as root:
			result = logs.tail(self._write(root, 1000), lines=5)
			self.assertEqual(result["lines"], [f"line {i}" for i in range(995, 1000)])

	def test_reads_across_chunk_boundaries(self):
		"""The seek-backwards loop has to keep going until it has enough."""
		with tempfile.TemporaryDirectory() as root:
			# Comfortably more than one TAIL_CHUNK of data.
			path = self._write(root, 20000)
			result = logs.tail(path, lines=500)
			self.assertEqual(len(result["lines"]), 500)
			self.assertEqual(result["lines"][-1], "line 19999")

	def test_a_file_shorter_than_the_request_returns_all_of_it(self):
		with tempfile.TemporaryDirectory() as root:
			result = logs.tail(self._write(root, 3), lines=100)
			self.assertEqual(result["lines"], ["line 0", "line 1", "line 2"])
			self.assertFalse(result["truncated"])

	def test_an_empty_file_is_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": ""})
			result = logs.tail(os.path.join(root, "logs", "worker.log"))
			self.assertEqual(result["lines"], [])
			self.assertIsNone(result["error"])

	def test_a_missing_file_reports_rather_than_raises(self):
		result = logs.tail("/nonexistent-log-for-tests.log")
		self.assertIsNotNone(result["error"])
		self.assertEqual(result["lines"], [])

	def test_the_line_count_is_capped(self):
		with tempfile.TemporaryDirectory() as root:
			result = logs.tail(self._write(root, 20), lines=999999)
			self.assertLessEqual(len(result["lines"]), logs.MAX_LINES)

	def test_invalid_bytes_do_not_break_the_read(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": ""})
			path = os.path.join(root, "logs", "worker.log")
			with open(path, "wb") as handle:
				handle.write(b"good\n\xff\xfe broken\ngood again\n")
			self.assertEqual(len(logs.tail(path)["lines"]), 3)


class TestSearch(unittest.TestCase):
	def test_matches_are_case_insensitive(self):
		"""Nobody remembers whether it said Error or ERROR."""
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "ERROR one\nfine\nerror two\n"})
			result = logs.tail(os.path.join(root, "logs", "worker.log"), search="error")
			self.assertEqual(result["matched"], 2)
			self.assertEqual(result["lines"], ["ERROR one", "error two"])

	def test_reports_how_much_was_scanned(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "".join(f"line {i}\n" for i in range(50))})
			result = logs.tail(os.path.join(root, "logs", "worker.log"), search="line 4")
			self.assertEqual(result["scanned"], 50)

	def test_no_matches_is_an_empty_result_not_an_error(self):
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "nothing here\n"})
			result = logs.tail(os.path.join(root, "logs", "worker.log"), search="zzz")
			self.assertEqual(result["lines"], [])
			self.assertEqual(result["matched"], 0)
			self.assertIsNone(result["error"])

	def test_a_term_matching_everything_stays_bounded(self):
		"""Memory must be bounded by the result, not by the file."""
		with tempfile.TemporaryDirectory() as root:
			make_bench(root, {"worker.log": "".join(f"line {i}\n" for i in range(5000))})
			result = logs.tail(os.path.join(root, "logs", "worker.log"), lines=10, search="line")
			self.assertEqual(len(result["lines"]), 10)
			self.assertEqual(result["lines"][-1], "line 4999")
			self.assertTrue(result["truncated"])


if __name__ == "__main__":
	unittest.main()


class TestCompressedRotations(unittest.TestCase):
	"""`.log.gz` rotations are offered by the picker, so they must be readable.

	Opening one as text returned decompressed-looking garbage — a file the
	interface invited you to read and then could not."""

	def _make(self, root: str, count: int) -> str:
		import gzip as gziplib

		directory = os.path.join(root, "logs")
		os.makedirs(directory, exist_ok=True)
		path = os.path.join(directory, "worker.log.1.gz")
		with gziplib.open(path, "wt") as handle:
			handle.write("".join(f"old line {i}\n" for i in range(count)))
		return path

	def test_the_tail_of_a_gzipped_rotation_is_readable(self):
		with tempfile.TemporaryDirectory() as root:
			result = logs.tail(self._make(root, 1000), lines=5)
			self.assertIsNone(result["error"])
			self.assertEqual(result["lines"][-1], "old line 999")
			self.assertTrue(result["truncated"])

	def test_search_works_inside_a_gzipped_rotation(self):
		with tempfile.TemporaryDirectory() as root:
			result = logs.tail(self._make(root, 1000), lines=10, search="line 42")
			self.assertEqual(result["matched"], 11)

	def test_a_corrupt_archive_reports_rather_than_raises(self):
		with tempfile.TemporaryDirectory() as root:
			directory = os.path.join(root, "logs")
			os.makedirs(directory)
			path = os.path.join(directory, "worker.log.1.gz")
			with open(path, "wb") as handle:
				handle.write(b"not actually gzip")
			self.assertIsNotNone(logs.tail(path)["error"])
