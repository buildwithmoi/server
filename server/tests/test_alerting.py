# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""How findings reach a person, and whether they can act on one when it does.

Three separate failures are guarded here, and all three end the same way — a
monitoring system nobody reads:

  Too much.   Every Medium in the mailbox and the Criticals become invisible.
              So Critical and High alert immediately and the rest is batched.
  Too little. A finding that only ever appears in a console is a finding
              nobody sees, because nobody sits in front of this app's console.
              So the batch is actually sent, every day, including on quiet days
              — an absence only means something if presence was guaranteed.
  Too quiet.  Deduplication turns "tell me every scan" into "tell me once a
              day", which is right for noise and wrong for a Critical raised at
              3am that is still untouched at 6pm. So untouched Criticals
              escalate.

The last class is structural rather than behavioural: it walks every rules
module in the package and asserts that no finding can be constructed without a
runbook. An alert that says something is wrong and not what to do about it
gets acknowledged rather than acted on, and the invariant is easier to keep
with a test than with discipline.
"""

import ast
import pathlib
import unittest

from server.security import digest

SECURITY = pathlib.Path(__file__).resolve().parents[1] / "security"


def _item(severity="Critical", age_hours=1.0, **kwargs):
	fields = {
		"name": "evt",
		"severity": severity,
		"category": "persistence",
		"subject": "A thing happened",
		"occurrences": 1,
		"age_hours": age_hours,
		"runbook": "Do the thing.",
	}
	fields.update(kwargs)
	return digest.Item(**fields)


class TestRouting(unittest.TestCase):
	def test_critical_and_high_are_immediate_the_rest_are_batched(self):
		self.assertEqual(digest.IMMEDIATE, ("Critical", "High"))
		self.assertEqual(digest.BATCHED, ("Medium", "Info"))

	def test_every_severity_is_routed_somewhere(self):
		"""A severity in neither list is one that silently goes nowhere."""
		self.assertEqual(
			sorted(digest.IMMEDIATE + digest.BATCHED), sorted(digest.SEVERITY_ORDER)
		)


class TestEscalation(unittest.TestCase):
	def test_an_untouched_critical_escalates_within_a_working_day(self):
		self.assertFalse(digest.needs_escalation(_item(age_hours=2)))
		self.assertTrue(digest.needs_escalation(_item(age_hours=9)))

	def test_a_high_gets_a_full_day_first(self):
		"""A High means "look today", so escalating it at lunchtime is noise."""
		self.assertFalse(digest.needs_escalation(_item("High", age_hours=9)))
		self.assertTrue(digest.needs_escalation(_item("High", age_hours=25)))

	def test_mediums_never_escalate(self):
		"""Nobody routinely acknowledges a Medium.

		Escalating them would mean escalating almost everything, which is the
		same as escalating nothing.
		"""
		self.assertFalse(digest.needs_escalation(_item("Medium", age_hours=500)))
		self.assertFalse(digest.needs_escalation(_item("Info", age_hours=500)))
		self.assertIsNone(digest.escalation_threshold("Medium"))


class TestSubjectLine(unittest.TestCase):
	"""Often the only part that gets read."""

	def test_escalations_lead(self):
		d = digest.Digest(escalated=(_item(),), counts={"Info": 40})
		self.assertTrue(digest.subject_line(d, "x").startswith("[Escalated]"))

	def test_a_stopped_detector_outranks_ordinary_findings(self):
		d = digest.Digest(
			detectors=(digest.Detector("network", "Error", 90.0, True),), counts={"Medium": 3}
		)
		self.assertTrue(digest.subject_line(d, "x").startswith("[Detectors]"))

	def test_otherwise_the_worst_severity_present_leads(self):
		d = digest.Digest(counts={"Info": 9, "High": 1})
		self.assertTrue(digest.subject_line(d, "x").startswith("[High]"))

	def test_a_quiet_day_says_so_rather_than_saying_nothing(self):
		self.assertIn("Quiet", digest.subject_line(digest.Digest(), "x"))

	def test_singular_and_plural_are_both_readable(self):
		one = digest.subject_line(digest.Digest(counts={"High": 1}), "x")
		many = digest.subject_line(digest.Digest(counts={"High": 4}), "x")
		self.assertIn("1 new finding —", one)
		self.assertIn("4 new findings", many)


class TestComposition(unittest.TestCase):
	def test_escalations_are_marked_as_a_repeat_not_a_first_report(self):
		"""Otherwise the reader treats it as new and wonders what changed."""
		_, body = digest.compose(digest.Digest(escalated=(_item(age_hours=11),)), "x")
		self.assertIn("second time", body)

	def test_suppressions_are_always_listed(self):
		"""A suppression nobody remembers is a blind spot with a friendly name."""
		d = digest.Digest(
			suppressions=(digest.Suppression("Noisy thing", "filesystem", 36.0, "known build artefact"),)
		)
		_, body = digest.compose(d, "x")
		self.assertIn("Noisy thing", body)
		self.assertIn("another 36 hours", body)

	def test_an_expired_suppression_says_it_will_report_again(self):
		d = digest.Digest(suppressions=(digest.Suppression("Thing", "web", -1.0),))
		_, body = digest.compose(d, "x")
		self.assertIn("will report again", body)

	def test_a_quiet_digest_explains_why_it_was_sent_at_all(self):
		_, body = digest.compose(digest.Digest(), "x")
		self.assertIn("absence means something", body)

	def test_findings_are_html_escaped(self):
		"""Subjects carry log-derived text, and a log line is not a fact.

		sshd escapes control characters in a username but not much else, so a
		subject can contain whatever a client chose to send.
		"""
		d = digest.Digest(new_items=(_item(subject="<img src=x onerror=alert(1)>"),))
		_, body = digest.compose(d, "x")
		self.assertNotIn("<img", body)
		self.assertIn("&lt;img", body)

	def test_the_host_name_is_escaped_too(self):
		_, body = digest.compose(digest.Digest(host="<b>evil</b>"), "x")
		self.assertNotIn("<b>evil", body)

	def test_is_quiet_is_not_fooled_by_a_stopped_detector(self):
		"""Nothing raised because nothing is looking is not a quiet day."""
		d = digest.Digest(detectors=(digest.Detector("network", "Error", 90.0, True),))
		self.assertFalse(d.is_quiet)


class TestEveryFindingCarriesARunbook(unittest.TestCase):
	"""Structural, across every rules module in the package.

	An alert that says something is wrong and not what to do about it gets
	acknowledged rather than acted on. Each rules module has its own test for
	this over the findings it happens to produce; this one reads the source and
	asserts that no finding can be constructed WITHOUT one, including on the
	branches no test happens to reach.
	"""

	def _rule_modules(self):
		return sorted(SECURITY.glob("*rules*.py"))

	def test_there_are_rules_modules_to_check(self):
		"""Guards against the glob silently matching nothing."""
		self.assertGreaterEqual(len(self._rule_modules()), 5)

	def test_no_finding_is_constructed_without_a_runbook(self):
		offenders = []
		for path in self._rule_modules():
			tree = ast.parse(path.read_text())
			for node in ast.walk(tree):
				if not isinstance(node, ast.Call):
					continue
				name = getattr(node.func, "id", getattr(node.func, "attr", ""))
				if name not in ("Finding", "_finding"):
					continue

				keywords = {k.arg for k in node.keywords}
				# Positional: (severity, subject, detail, runbook[, category])
				has_runbook = len(node.args) >= 4 or "runbook" in keywords
				if not has_runbook:
					offenders.append(f"{path.name}:{node.lineno}")

		self.assertEqual(offenders, [], f"findings built with no runbook: {offenders}")

	def test_no_runbook_is_an_empty_string(self):
		"""A blank runbook passes the arity check and helps nobody."""
		offenders = []
		for path in self._rule_modules():
			tree = ast.parse(path.read_text())
			for node in ast.walk(tree):
				if not isinstance(node, ast.Call):
					continue
				name = getattr(node.func, "id", getattr(node.func, "attr", ""))
				if name not in ("Finding", "_finding") or len(node.args) < 4:
					continue
				runbook = node.args[3]
				if isinstance(runbook, ast.Constant) and not str(runbook.value).strip():
					offenders.append(f"{path.name}:{node.lineno}")

		self.assertEqual(offenders, [], f"blank runbooks: {offenders}")

	def test_every_rules_module_declares_its_category(self):
		"""Findings are grouped and routed by category.

		One that arrives with an empty category is one that cannot be filtered
		out later when it turns out to be noisy.
		"""
		missing = []
		for path in self._rule_modules():
			tree = ast.parse(path.read_text())
			declared = any(
				isinstance(node, ast.Assign)
				and any(getattr(t, "id", "") == "CATEGORY" for t in node.targets)
				for node in tree.body
			)
			imported = "CATEGORY" in path.read_text()
			if not (declared or imported):
				missing.append(path.name)
		self.assertEqual(missing, [])
