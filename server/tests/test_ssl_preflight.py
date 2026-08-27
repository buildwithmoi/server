# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A pre-flight must not refuse a state the run itself creates.

The plan announced four steps — turn on DNS multitenancy, tell the site its
domain, regenerate nginx, issue the certificate — and the check above them
stopped the run because DNS multitenancy was off. The step that turns it on was
three rows below the refusal, on the same screen, marked "Did not run."

That is a specific and repeatable mistake, not a typo: a guard written when the
job could not fix the thing, left in place after it could.
"""

from __future__ import annotations

import inspect
import unittest

from server.bench import installer, steps


class ThePreflightChecksWhatItCannotFix(unittest.TestCase):
	def test_it_no_longer_refuses_on_multitenancy(self):
		source = inspect.getsource(installer._preflight_ssl)
		self.assertNotIn("is not DNS-multitenant, and bench refuses", source)
		# It still SAYS so — as a note about what the run will do first.
		self.assertIn("will be turned on first", source)

	def test_it_no_longer_refuses_on_a_domain_the_job_adds(self):
		source = inspect.getsource(installer._preflight_ssl)
		self.assertNotIn("add it with `bench setup add-domain` first", source)
		self.assertIn("will be added to", source)

	def test_it_still_refuses_what_the_job_genuinely_cannot_do(self):
		source = inspect.getsource(installer._preflight_ssl)
		# certbot missing, no root, and a name Let's Encrypt will never
		# certify are all outside the job's reach — and one of them costs a
		# rate limit that outlasts the mistake.
		self.assertIn("certbot is not installed", source)
		self.assertIn("has_passwordless_sudo()", source)
		self.assertIn("is not a public domain name", source)
		self.assertIn('dns["level"] == "danger"', source)

	def test_the_sudo_refusal_points_at_the_file(self):
		source = inspect.getsource(installer._preflight_ssl)
		self.assertIn("SUDOERS_PATH", source)
		self.assertIn("grants nothing else", source)


class ThePlanAndTheGuardAgree(unittest.TestCase):
	"""Whatever the plan promises to do, the check must not refuse."""

	def test_every_prepared_step_is_absent_from_the_refusals(self):
		announced = {s.key for s in steps.for_ssl("issue", dry_run=False, prepare=True)}
		self.assertEqual(announced & {"multitenant", "domain", "nginx"}, {"multitenant", "domain", "nginx"})

		refusals = inspect.getsource(installer._preflight_ssl)
		for phrase in ("dns_multitenant on` first", "add-domain` first"):
			self.assertNotIn(phrase, refusals)


if __name__ == "__main__":
	unittest.main()
