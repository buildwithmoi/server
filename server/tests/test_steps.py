# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Step state machine tests.

Frappe-free. The clock is injected so durations are exact rather than
approximately-not-zero, which is what lets these assert real numbers.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from server.bench import steps


class Clock:
	"""A clock that only moves when the test says so."""

	def __init__(self):
		self.now = datetime(2026, 8, 25, 12, 0, 0)

	def __call__(self) -> datetime:
		return self.now

	def advance(self, seconds: float) -> None:
		self.now += timedelta(seconds=seconds)


def plan(clock=None, *keys):
	return steps.Plan(steps.make(*[(k, k.title(), "") for k in keys]), now=clock)


class TestLifecycle(unittest.TestCase):
	def setUp(self):
		self.clock = Clock()
		self.plan = plan(self.clock, "one", "two", "three")

	def test_every_step_starts_pending(self):
		"""The plan is announced before the work, not grown as it happens.

		Seeing that a restore is about to take a backup first is only useful
		while there is still time to cancel.
		"""
		self.assertEqual([s.status for s in self.plan.steps], [steps.PENDING] * 3)

	def test_running_then_success_records_a_duration(self):
		self.plan.start("one")
		self.assertEqual(self.plan.get("one").status, steps.RUNNING)
		self.clock.advance(4.5)
		self.plan.succeed("one")

		step = self.plan.get("one")
		self.assertEqual(step.status, steps.SUCCESS)
		self.assertEqual(step.duration, 4.5)

	def test_starting_the_next_step_closes_the_previous_one(self):
		"""Otherwise a step spins forever in the interface."""
		self.plan.start("one")
		self.clock.advance(2)
		self.plan.start("two")

		self.assertEqual(self.plan.get("one").status, steps.SUCCESS)
		self.assertEqual(self.plan.get("one").duration, 2)
		self.assertEqual(self.plan.get("two").status, steps.RUNNING)

	def test_failure_records_its_reason(self):
		self.plan.start("one")
		self.plan.fail("one", "the remote refused")
		self.assertEqual(self.plan.get("one").status, steps.FAILURE)
		self.assertEqual(self.plan.get("one").detail, "the remote refused")

	def test_a_closed_step_is_never_reopened(self):
		self.plan.start("one")
		self.plan.fail("one", "broke")
		self.plan.succeed("one", "actually fine")
		self.assertEqual(self.plan.get("one").status, steps.FAILURE)
		self.assertEqual(self.plan.get("one").detail, "broke")

	def test_abandon_marks_the_rest_skipped(self):
		"""A job that stops must not leave steps looking like they are running."""
		self.plan.start("one")
		self.plan.succeed("one")
		self.plan.start("two")
		self.plan.abandon("stopped here")

		self.assertEqual(self.plan.get("two").status, steps.FAILURE)
		self.assertEqual(self.plan.get("three").status, steps.SKIPPED)

	def test_abandon_leaves_completed_steps_alone(self):
		self.plan.start("one")
		self.plan.succeed("one")
		self.plan.abandon("stopped")
		self.assertEqual(self.plan.get("one").status, steps.SUCCESS)

	def test_an_unplanned_step_is_still_recorded(self):
		"""Better a step nobody announced than work that happens invisibly."""
		self.plan.start("surprise")
		self.assertIsNotNone(self.plan.get("surprise"))
		self.assertEqual(self.plan.get("surprise").status, steps.RUNNING)

	def test_skip_only_applies_to_a_step_that_never_ran(self):
		self.plan.start("one")
		self.plan.succeed("one")
		self.plan.skip("one", "not needed")
		self.assertEqual(self.plan.get("one").status, steps.SUCCESS)


class TestOutput(unittest.TestCase):
	def setUp(self):
		self.plan = plan(Clock(), "one", "two")

	def test_output_attaches_to_whatever_is_running(self):
		self.plan.start("one")
		self.plan.line("hello")
		self.plan.start("two")
		self.plan.line("world")

		self.assertEqual(self.plan.get("one").output, ["hello"])
		self.assertEqual(self.plan.get("two").output, ["world"])

	def test_output_before_any_step_is_dropped_rather_than_crashing(self):
		self.plan.line("orphan")
		self.assertEqual(self.plan.get("one").output, [])

	def test_long_output_keeps_the_tail_and_says_so(self):
		"""The end of a failing command is the part that says why."""
		self.plan.start("one")
		for i in range(steps.MAX_STEP_LINES + 50):
			self.plan.line(f"line {i}")

		output = self.plan.get("one").output
		self.assertLessEqual(len(output), steps.MAX_STEP_LINES + 1)
		self.assertIn("earlier lines", output[0])
		self.assertEqual(output[-1], f"line {steps.MAX_STEP_LINES + 49}")


class TestSummary(unittest.TestCase):
	def test_a_failure_names_the_step_that_failed(self):
		p = plan(Clock(), "one", "two")
		p.start("one")
		p.succeed("one")
		p.start("two")
		p.fail("two", "nope")
		self.assertEqual(p.summary(), "Failed at: Two")

	def test_success_counts_what_completed(self):
		p = plan(Clock(), "one", "two")
		p.start("one")
		p.succeed("one")
		self.assertEqual(p.summary(), "1 of 2 steps completed")


class TestPlans(unittest.TestCase):
	def test_clone_only_includes_the_install_step_when_asked(self):
		self.assertNotIn("install", [s.key for s in steps.for_clone(False)])
		self.assertIn("install", [s.key for s in steps.for_clone(True)])

	def test_restore_only_includes_the_safety_backup_when_asked(self):
		self.assertNotIn("safety", [s.key for s in steps.for_restore(False)])
		self.assertIn("safety", [s.key for s in steps.for_restore(True)])

	def test_ssl_renew_is_titled_by_whether_it_is_a_rehearsal(self):
		self.assertEqual(steps.for_ssl("renew", True)[-1].title, "Rehearse renewal")
		self.assertEqual(steps.for_ssl("renew", False)[-1].title, "Renew the certificates")

	def test_every_plan_starts_with_a_check(self):
		"""Nothing runs before something has confirmed it should."""
		for made in (
			steps.for_clone(True),
			steps.for_pull(),
			steps.for_command("X"),
			steps.for_ssl("issue", False),
			steps.for_restore(True),
		):
			self.assertEqual(made[0].key, "check")

	def test_keys_are_unique_within_a_plan(self):
		"""Duplicates would make get() ambiguous and close the wrong step."""
		for made in (steps.for_clone(True), steps.for_restore(True)):
			keys = [s.key for s in made]
			self.assertEqual(len(keys), len(set(keys)))


class TestSerialisation(unittest.TestCase):
	def test_as_list_is_json_ready(self):
		import json

		p = plan(Clock(), "one")
		p.start("one")
		p.line("output")
		p.succeed("one")
		# Round-trips, because this is stored in a Code field and read by the
		# browser rather than passed around in memory.
		self.assertEqual(json.loads(json.dumps(p.as_list()))[0]["output"], "output")


if __name__ == "__main__":
	unittest.main()
