# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The deployment transcript: one document that explains itself.

A build that went wrong is usually read by somebody who was not watching it —
often days later, often not the person who ran it. These tests are mostly
about that reader: that the document says who and when without being asked,
that it survives being pasted into a chat window, and that nothing secret
travels with it.
"""

import unittest

from server.bench import transcript

REQUEST = {
	"name": "AIR-00261",
	"operation": "Provision",
	"app_name": "Provision · fb-16-demo",
	"host": "prod-1",
	"provision_bench_name": "fb-16-demo",
	"provision_site_name": "demo.test",
	"provision_frappe_version": "16",
	"provision_port_index": 9,
	"provision_apps": "Carbonite|server|version-16",
	"owner": "obed@example.com",
	"started_at": "2026-08-26 14:02:11",
	"finished_at": "2026-08-26 14:09:40",
	"duration": 449,
	"status": "Failed",
	"exit_code": 1,
	"error_summary": "bench new-site exited 1",
	"command": "bench new-site demo.test --db-root-password ********",
	"output": "line one\nline two",
}

STEPS = [
	{"title": "Create the bench", "status": "Success", "duration": 321},
	{"title": "Create the site", "status": "Failure", "duration": 12, "detail": "Access denied"},
	{"title": "Re-read the bench", "status": "Skipped", "detail": "Did not run."},
]


class TestWhatTheReaderNeedsFirst(unittest.TestCase):
	def test_who_ran_it_and_when(self):
		"""The two questions a log nobody watched always raises."""
		text = transcript.build(REQUEST, STEPS)
		self.assertIn("obed@example.com", text)
		self.assertIn("2026-08-26 14:02:11", text)

	def test_the_outcome_is_stated_not_inferred(self):
		text = transcript.build(REQUEST, STEPS)
		self.assertIn("Failed", text)
		self.assertIn("Exit code", text)

	def test_the_reason_appears_above_the_output(self):
		"""Somebody skimming should not have to read 900 lines to reach it."""
		text = transcript.build(REQUEST, STEPS)
		self.assertLess(text.index("bench new-site exited 1"), text.index("line one"))

	def test_it_says_which_bench_and_which_frappe(self):
		"""The raw log opens mid-clone and never mentions either."""
		text = transcript.build(REQUEST, STEPS)
		self.assertIn("fb-16-demo", text)
		self.assertIn("version-16", text)

	def test_the_ports_are_spelled_out_from_the_index(self):
		"""`provision_port_index: 9` means nothing to a reader; 8009 does."""
		self.assertIn("8009", transcript.build(REQUEST, STEPS))


class TestSteps(unittest.TestCase):
	def test_each_step_shows_its_outcome_and_timing(self):
		text = transcript.build(REQUEST, STEPS)
		self.assertIn("Create the bench", text)
		self.assertIn("5m 21s", text)

	def test_the_failing_step_is_marked_in_text_not_only_by_position(self):
		"""The document is read as plain text, where colour does not exist."""
		self.assertIn("[FAIL]", transcript.build(REQUEST, STEPS))

	def test_a_run_with_no_steps_still_renders(self):
		"""A job that died before its plan was stored still has a log."""
		self.assertIn("AIR-00261", transcript.build(REQUEST, []))


class TestNothingSecretTravels(unittest.TestCase):
	"""This document is built to be pasted into a chat window."""

	def test_the_command_is_taken_as_stored_already_redacted(self):
		text = transcript.build(REQUEST, STEPS)
		self.assertIn("--db-root-password ********", text)

	def test_a_password_field_is_never_rendered_even_if_present(self):
		"""The endpoint strips them; this asserts the formatter never invents
		a place to show one, so the two cannot drift apart."""
		leaky = dict(REQUEST, provision_db_password="hunter2", restore_db_password="hunter2")
		self.assertNotIn("hunter2", transcript.build(leaky, STEPS))


class TestFormatting(unittest.TestCase):
	def test_a_missing_value_reads_as_a_dash_not_as_none(self):
		text = transcript.build({"name": "AIR-1", "operation": "Provision"}, [])
		self.assertNotIn("None", text)
		self.assertIn("—", text)

	def test_durations_are_human(self):
		self.assertEqual(transcript._duration(45), "45s")
		self.assertEqual(transcript._duration(449), "7m 29s")
		self.assertEqual(transcript._duration(7200), "2h 00m")
		self.assertEqual(transcript._duration(0), "—")
		self.assertEqual(transcript._duration(None), "—")

	def test_an_empty_output_says_so_rather_than_ending_blank(self):
		"""A transcript that just stops looks truncated."""
		self.assertIn("nothing was captured", transcript.build({"name": "x"}, []))

	def test_the_filename_sorts_and_names_the_bench(self):
		name = transcript.filename(REQUEST)
		self.assertTrue(name.startswith("20260826_140211"))
		self.assertIn("fb-16-demo", name)
		self.assertTrue(name.endswith(".txt"))

	def test_the_filename_survives_an_awkward_bench_name(self):
		"""It becomes a download; a slash in it would be a path."""
		name = transcript.filename({"provision_bench_name": "a/b c", "name": "AIR-1"})
		self.assertNotIn("/", name)
		self.assertNotIn(" ", name)
