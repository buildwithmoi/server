# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The parts of off-box forwarding and the watchdog that need no site.

WHY THESE TWO THINGS ARE TESTED TOGETHER. They are one idea: everything the
detectors produce runs on the host they watch, so an attacker with root can
stop the scheduler, edit the findings, or both. Forwarding puts a copy
somewhere else at the moment of writing; the heartbeat lets something else
notice when this host goes quiet. Neither is worth much alone.

What is covered here is the reasoning, not the plumbing -- the payload shape a
collector depends on, and the tolerance that decides whether a silent detector
reads as healthy. The HTTP path itself was exercised live against a throwaway
collector (success, HTTP 503, and a retry that drained the backlog).
"""

import unittest
from types import SimpleNamespace

from server.security.forward import _payload
from server.server.doctype.ingest_heartbeat.ingest_heartbeat import LATE_MULTIPLIER, lateness


def _event(**overrides):
	base = {
		"name": "abc123",
		"host": "server-01",
		"event_time": "2026-08-25 04:00:00",
		"severity": "Critical",
		"category": "persistence",
		"subject": "New systemd unit owned by no package",
		"detail": "/etc/systemd/system/update.service",
		"runbook": "Confirm you installed it.",
		"occurrences": 2,
		"source_doctype": "Persistence Item",
		"source_name": "PI-0001",
	}
	base.update(overrides)
	return SimpleNamespace(**base)


class TestForwardPayload(unittest.TestCase):
	def test_carries_what_the_collector_needs(self):
		payload = _payload(_event())
		self.assertEqual(payload["event_id"], "abc123")
		self.assertEqual(payload["host"], "server-01")
		self.assertEqual(payload["severity"], "Critical")
		self.assertEqual(payload["occurrences"], 2)

	def test_runbook_travels_with_the_finding(self):
		"""Whoever reads this may no longer have access to the host.

		That is exactly when the finding matters most, so the record has to
		explain itself without the machine it came from.
		"""
		self.assertEqual(_payload(_event())["runbook"], "Confirm you installed it.")

	def test_no_field_is_ever_none(self):
		"""A None in the payload becomes `null` and breaks strict collectors.

		Every optional field is empty-stringed for that reason; this test is
		what stops someone removing the `or ""` as redundant.
		"""
		blank = _event(
			host=None, detail=None, runbook=None, occurrences=None, source_doctype=None, source_name=None
		)
		payload = _payload(blank)
		self.assertNotIn(None, payload.values())
		self.assertEqual(payload["occurrences"], 1)

	def test_payload_carries_no_secret(self):
		"""The token authenticates the request; it must never be in the body.

		Forwarding sends findings off the box, which means the payload is the
		one part of this app that routinely leaves it.
		"""
		flat = " ".join(str(v).lower() for v in _payload(_event()).values())
		for word in ("token", "password", "secret", "bearer"):
			self.assertNotIn(word, flat)


class TestLateness(unittest.TestCase):
	def test_on_schedule_is_not_late(self):
		self.assertIsNone(lateness(300, 300))

	def test_one_missed_run_is_tolerated(self):
		"""A briefly busy scheduler is the common case, not an intrusion.

		Alerting on every skipped tick is how a monitoring system teaches its
		operator to ignore it.
		"""
		self.assertIsNone(lateness(600, 300))

	def test_well_past_the_window_is_late(self):
		self.assertIsNotNone(lateness(2400, 300))

	def test_late_is_measured_against_the_schedule(self):
		"""Not against the tolerance.

		"35 minutes late" for a 5-minute detector is the sentence an operator
		can act on, and it stays true if LATE_MULTIPLIER is ever retuned.
		"""
		self.assertEqual(lateness(2400, 300), 2100)

	def test_boundary_does_not_alert(self):
		self.assertIsNone(lateness(300 * LATE_MULTIPLIER, 300))
		self.assertIsNotNone(lateness(300 * LATE_MULTIPLIER + 1, 300))

	def test_unscheduled_detector_is_never_late(self):
		"""expected_every of 0 means "no schedule recorded yet".

		Dividing that into a lateness figure would report every such row as
		infinitely overdue on the first scan after an upgrade.
		"""
		self.assertIsNone(lateness(99999, 0))
