# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""401 and 403 are different answers, and one of them was a checkbox.

A migration stopped with "The remote refused the credentials. Check the API key
and secret, and that the user they belong to is a System Manager there." The
credentials were correct and the user was a System Manager. What had actually
happened is that `prepare_backup_for_transfer` runs `bench backup`, so it is
gated on that server's own install interlock — and frappe returns a
PermissionError for that, which is an HTTP 403, which this client reported as a
login failure.
"""

from __future__ import annotations

import json
import unittest

from server.remote import client


def _frappe_error(message: str, exception: str = "frappe.exceptions.PermissionError") -> str:
	"""A refusal shaped the way frappe actually sends one."""
	return json.dumps(
		{
			"exception": f"{exception}: {message}",
			"_server_messages": json.dumps(
				[json.dumps({"message": f"<div>{message}</div>", "title": "Installs Disabled"})]
			),
		}
	)


class _Response:
	def __init__(self, code: int, body: str = ""):
		self.code = code
		self._body = body.encode()

	def read(self) -> bytes:
		return self._body


INTERLOCK = (
	"App installs are disabled. Turn on Allow App Installs in Server Settings "
	"before running an App Install Request."
)


class WhatTheRemoteActuallySaid(unittest.TestCase):
	def test_frappes_own_message_is_dug_out_of_server_messages(self):
		# It lives in `_server_messages`: a JSON string holding a list of JSON
		# strings, holding HTML. Reading `exception` instead gave
		# "frappe.exceptions.PermissionError" — a class name, to an operator.
		self.assertEqual(client._remote_said(_frappe_error(INTERLOCK)), INTERLOCK)

	def test_the_html_frappe_wraps_it_in_is_stripped(self):
		said = client._remote_said(_frappe_error("<b>Nope</b><br>Try again"))
		self.assertNotIn("<", said)
		self.assertIn("Nope", said)

	def test_a_body_that_is_not_json_still_says_something(self):
		self.assertIn("gateway", client._remote_said("502 bad gateway").lower())

	def test_an_empty_body_says_nothing_rather_than_inventing(self):
		self.assertEqual(client._remote_said(""), "")


class TheTwoRefusalsAreToldApart(unittest.TestCase):
	def test_403_leads_with_what_the_remote_said(self):
		text = client._explain_remote(_Response(403, _frappe_error(INTERLOCK)))
		self.assertIn("Allow App Installs", text)
		# And says plainly that this was NOT a login problem, which is the
		# wrong turn the old message sent people down.
		self.assertIn("credentials were accepted", text)

	def test_401_is_the_one_that_is_about_credentials(self):
		text = client._explain_remote(_Response(401, ""))
		self.assertIn("API key and secret", text)
		self.assertNotIn("credentials were accepted", text)

	def test_404_still_points_at_the_version(self):
		self.assertIn("older version", client._explain_remote(_Response(404, "")))


class AskedBeforeTheJobStarts(unittest.TestCase):
	"""The interlock is off by default, so this is the ordinary case."""

	def test_identity_reports_it(self):
		import inspect

		from server import api

		self.assertIn('"installs_allowed"', inspect.getsource(api.server_identity))

	def test_the_preflight_refuses_on_it_by_name(self):
		import inspect

		from server.bench import installer

		source = inspect.getsource(installer._preflight_restore)
		self.assertIn('check.data.get("installs_allowed") is False', source)
		self.assertIn("Allow App Installs", source)

	def test_absent_is_not_off(self):
		# An older remote does not report the field at all, and treating that
		# as "switched off" would refuse a server that works.
		import inspect

		from server.bench import installer

		self.assertIn("is False", inspect.getsource(installer._preflight_restore))


if __name__ == "__main__":
	unittest.main()
