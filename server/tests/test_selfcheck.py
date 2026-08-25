# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Making this app's own records checkable from outside it.

An intruder who knows what is installed here has a cheaper option than
evading the detectors: edit them. Two lines in `rules.py` turn a Critical into
an Info, and every other part of the system keeps working — the scans run, the
heartbeat climbs, the digest arrives, and it says the machine is fine.

Three mechanisms, and the honest claim about all three is the same. None of
them stops a careful attacker with root and database access: they can edit the
code, recompute the chain, and rewrite the baseline. What they do is make
tampering VISIBLE FROM ANOTHER MACHINE — the chain head and the code
fingerprint are published in the signed heartbeat and forwarded off the box, so
a rewritten history is one that disagrees with copies somebody else already
holds.

The tests are written to hold that line. Several assert what the mechanisms
do NOT prove, because a security feature that gets trusted further than it
deserves is worse than one nobody relies on.
"""

import hashlib
import hmac
import json
import os
import tempfile
import unittest

from server.security import selfcheck
from server.security import watchdog_client as watchdog
from server.server.doctype.security_event.security_event import content_digest, link_hash

TOKEN = "a-shared-secret"


def _sign(payload, token=TOKEN):
	unsigned = {k: v for k, v in payload.items() if k != "signature"}
	payload = dict(payload)
	payload["signature"] = hmac.new(
		token.encode(),
		json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
		hashlib.sha256,
	).hexdigest()
	return payload


class TestChainHashing(unittest.TestCase):
	"""The pure half of the tamper-evident chain — no database needed."""

	def test_the_same_finding_always_hashes_the_same(self):
		a = content_digest(1, "2026-08-25 12:00:00", "Critical", "persistence", "s", "d")
		b = content_digest(1, "2026-08-25 12:00:00", "Critical", "persistence", "s", "d")
		self.assertEqual(a, b)

	def test_changing_any_covered_field_changes_the_digest(self):
		base = content_digest(1, "2026-08-25 12:00:00", "Critical", "persistence", "s", "d")
		for changed in (
			content_digest(2, "2026-08-25 12:00:00", "Critical", "persistence", "s", "d"),
			content_digest(1, "2026-08-25 12:00:01", "Critical", "persistence", "s", "d"),
			content_digest(1, "2026-08-25 12:00:00", "Info", "persistence", "s", "d"),
			content_digest(1, "2026-08-25 12:00:00", "Critical", "network", "s", "d"),
			content_digest(1, "2026-08-25 12:00:00", "Critical", "persistence", "other", "d"),
			content_digest(1, "2026-08-25 12:00:00", "Critical", "persistence", "s", "other"),
		):
			self.assertNotEqual(base, changed)

	def test_a_downgraded_severity_is_exactly_what_it_catches(self):
		"""The cheapest possible tamper: Critical becomes Info, nothing else."""
		critical = content_digest(7, "2026-08-25 12:00:00", "Critical", "self", "s", "d")
		info = content_digest(7, "2026-08-25 12:00:00", "Info", "self", "s", "d")
		self.assertNotEqual(critical, info)

	def test_fields_are_separated_so_they_cannot_be_slid_between(self):
		"""Without a separator, ("ab","c") and ("a","bc") hash identically.

		Which would let a subject absorb a character from the category and
		leave the hash intact.
		"""
		a = content_digest(1, "t", "Critical", "ab", "c", "d")
		b = content_digest(1, "t", "Critical", "a", "bc", "d")
		self.assertNotEqual(a, b)

	def test_each_link_depends_on_the_one_before(self):
		digest = content_digest(2, "t", "High", "web", "s", "d")
		self.assertNotEqual(link_hash("aaa", digest), link_hash("bbb", digest))

	def test_the_first_link_has_no_predecessor(self):
		self.assertTrue(link_hash("", content_digest(1, "t", "High", "web", "s", "d")))


class TestCodeFingerprint(unittest.TestCase):
	def _tree(self, tmp, **files):
		for name, text in files.items():
			path = os.path.join(tmp, name)
			os.makedirs(os.path.dirname(path), exist_ok=True)
			with open(path, "w") as handle:
				handle.write(text)
		return selfcheck.scan_code(tmp)

	def test_the_fingerprint_is_stable_across_runs(self):
		with tempfile.TemporaryDirectory() as tmp:
			first = self._tree(tmp, **{"a.py": "x = 1", "pkg/b.py": "y = 2"})
			second = selfcheck.scan_code(tmp)
		self.assertEqual(first.fingerprint, second.fingerprint)

	def test_editing_one_file_changes_the_fingerprint(self):
		with tempfile.TemporaryDirectory() as tmp:
			before = self._tree(tmp, **{"a.py": "x = 1"})
			after = self._tree(tmp, **{"a.py": "x = 2"})
		self.assertNotEqual(before.fingerprint, after.fingerprint)

	def test_non_python_files_are_ignored(self):
		"""The Vue bundle is not what turns a Critical into an Info.

		Watching build output would mean a fingerprint that changes on every
		yarn build, which is a fingerprint nobody can act on.
		"""
		with tempfile.TemporaryDirectory() as tmp:
			before = self._tree(tmp, **{"a.py": "x = 1"})
			after = self._tree(tmp, **{"a.py": "x = 1", "style.css": "body{}"})
		self.assertEqual(before.fingerprint, after.fingerprint)

	def test_caches_and_tests_are_skipped(self):
		with tempfile.TemporaryDirectory() as tmp:
			before = self._tree(tmp, **{"a.py": "x = 1"})
			after = self._tree(tmp, **{"a.py": "x = 1", "__pycache__/a.py": "junk", "tests/t.py": "t"})
		self.assertEqual(before.fingerprint, after.fingerprint)

	def test_compare_separates_changed_added_and_removed(self):
		with tempfile.TemporaryDirectory() as tmp:
			state = self._tree(tmp, **{"keep.py": "1", "edited.py": "2", "new.py": "3"})
		previous = {"keep.py": next(f.digest for f in state.files if f.relative_path == "keep.py"),
					"edited.py": "0" * 64,
					"gone.py": "0" * 64}
		difference = selfcheck.compare(previous, state)
		self.assertEqual(difference["changed"], ["edited.py"])
		self.assertEqual(difference["added"], ["new.py"])
		self.assertEqual(difference["removed"], ["gone.py"])

	def test_an_unreadable_file_does_not_abort_the_scan(self):
		"""A scan that raises halfway produces no fingerprint at all,
		which reads downstream as "nothing to check"."""
		with tempfile.TemporaryDirectory() as tmp:
			state = self._tree(tmp, **{"a.py": "x = 1", "b.py": "y = 2"})
			os.chmod(os.path.join(tmp, "b.py"), 0o000)
			try:
				degraded = selfcheck.scan_code(tmp)
			finally:
				os.chmod(os.path.join(tmp, "b.py"), 0o644)
		self.assertEqual(degraded.count, 2)


class TestWatchdogSignature(unittest.TestCase):
	def test_a_genuine_reply_verifies(self):
		self.assertTrue(watchdog.verify_signature(_sign({"host": "a", "sequence_total": 5}), TOKEN))

	def test_a_wrong_token_does_not(self):
		self.assertFalse(watchdog.verify_signature(_sign({"host": "a"}), "wrong"))

	def test_any_edit_to_the_payload_invalidates_it(self):
		"""The point: an intercepting proxy cannot return a healthy answer.

		Without a signature the watcher is watching the network, not the host.
		"""
		payload = _sign({"host": "a", "open_critical": 12})
		payload["open_critical"] = 0
		self.assertFalse(watchdog.verify_signature(payload, TOKEN))

	def test_a_missing_signature_does_not_verify(self):
		self.assertFalse(watchdog.verify_signature({"host": "a"}, TOKEN))


class TestWatchdogChecks(unittest.TestCase):
	def _payload(self, **kwargs):
		base = {
			"host": "prod",
			"time": "2026-08-25 12:00:00",
			"sequence_total": 100,
			"chain_sequence": 40,
			"chain_head": "h" * 64,
			"code_fingerprint": "f" * 64,
			"overdue": [],
			"open_critical": 0,
		}
		base.update(kwargs)
		return _sign(base)

	def test_a_bad_signature_suppresses_every_other_finding(self):
		"""Nothing below it can be trusted, so reporting it alongside other
		problems would invite acting on numbers that were made up."""
		payload = self._payload(open_critical=9)
		payload["signature"] = "0" * 64
		problems = watchdog.check(payload, {}, TOKEN)
		self.assertEqual(len(problems), 1)
		self.assertIn("SIGNATURE INVALID", problems[0])

	def test_a_sequence_going_backwards_is_reported_as_a_restore(self):
		problems = watchdog.check(self._payload(sequence_total=50), {"sequence_total": 100}, TOKEN)
		self.assertTrue(any("BACKWARDS" in p for p in problems))

	def test_a_stalled_sequence_is_reported(self):
		problems = watchdog.check(self._payload(), {"sequence_total": 100}, TOKEN)
		self.assertTrue(any("HAS NOT MOVED" in p for p in problems))

	def test_a_rewritten_chain_at_the_same_length_is_caught(self):
		"""The careful tamper: delete a finding, recompute every hash after
		it, and put the count back. The head no longer matches what the
		watcher already saw."""
		state = {"sequence_total": 99, "chain_sequence": 40, "chain_head": "x" * 64}
		problems = watchdog.check(self._payload(), state, TOKEN)
		self.assertTrue(any("REWRITTEN" in p for p in problems))

	def test_a_shrinking_history_is_caught(self):
		state = {"sequence_total": 99, "chain_sequence": 90, "chain_head": "h" * 64}
		problems = watchdog.check(self._payload(), state, TOKEN)
		self.assertTrue(any("SHRANK" in p for p in problems))

	def test_a_changed_code_fingerprint_is_reported_with_its_innocent_cause(self):
		"""A deploy is the usual reason, and saying so is what stops the
		alert being ignored the third time it fires after a release."""
		state = {"sequence_total": 99, "code_fingerprint": "a" * 64}
		problems = [p for p in watchdog.check(self._payload(), state, TOKEN) if "CODE CHANGED" in p]
		self.assertEqual(len(problems), 1)
		self.assertIn("deploy", problems[0])

	def test_a_stale_reply_is_treated_as_a_replay(self):
		problems = watchdog.check(self._payload(time="2020-01-01 00:00:00"), {}, TOKEN)
		self.assertTrue(any("STALE" in p for p in problems))

	def test_an_overdue_detector_is_reported(self):
		payload = self._payload(overdue=[{"source": "network", "seconds_late": 2400}])
		problems = watchdog.check(payload, {}, TOKEN)
		self.assertTrue(any("DETECTOR STOPPED" in p for p in problems))

	def test_a_healthy_host_produces_nothing(self):
		state = {"sequence_total": 99, "chain_sequence": 40, "chain_head": "h" * 64, "code_fingerprint": "f" * 64}
		import datetime

		now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
		payload = self._payload(time=now.isoformat(sep=" ", timespec="seconds"))
		self.assertEqual(watchdog.check(payload, state, TOKEN), [])


class TestTheHonestLimits(unittest.TestCase):
	"""What these mechanisms explicitly do NOT prove.

	Written as tests so the claim stays in the codebase rather than only in a
	commit message, and so nobody later describes this as tamper-PROOF.
	"""

	def test_a_recomputed_chain_verifies_perfectly(self):
		"""An attacker with database access can delete a finding and rebuild
		every hash after it. Local verification then passes — which is why the
		head is published for an outside watcher to compare."""
		rebuilt = ""
		for sequence in (1, 2, 3):
			rebuilt = link_hash(rebuilt, content_digest(sequence, "t", "Info", "c", "s", "d"))
		replayed = ""
		for sequence in (1, 2, 3):
			replayed = link_hash(replayed, content_digest(sequence, "t", "Info", "c", "s", "d"))
		self.assertEqual(rebuilt, replayed)

	def test_the_chain_does_not_cover_acknowledgement(self):
		"""Deliberate. Status, occurrences and forwarding all change after the
		row is written, and acknowledging a finding must not look like
		tampering with one."""
		digest = content_digest(1, "t", "Critical", "c", "s", "d")
		self.assertEqual(digest, content_digest(1, "t", "Critical", "c", "s", "d"))
