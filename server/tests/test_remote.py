# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Talking to another server, and moving a backup off it.

The transfer tests are about one failure in particular. frappe answers a
binary request by building a fresh response from a filename and a body — it
discards any status code or header the endpoint set. So there is no 206 to
distinguish a slice from a whole file and no `Content-Range` to read, and a
client that trusts `Content-Length` takes the first chunk for the entire
backup. It then writes a truncated archive which only fails at restore, hours
later, on the machine being migrated to.

That is not hypothetical — it is what the first version of this did, and it is
why the client counts to a size it was told separately rather than believing
the response.
"""

import os
import tempfile
import unittest

from server.remote.client import Progress, RemoteServer, Result


class TestResultNeverRaises(unittest.TestCase):
	"""A server being down is an ordinary Tuesday."""

	def test_an_unreachable_host_comes_back_as_a_result(self):
		result = RemoteServer("https://nowhere.invalid", "k", "s").call("server.api.server_identity")
		self.assertFalse(result.ok)
		self.assertIn("not answering", result.error)

	def test_the_frappe_message_wrapper_is_unwrapped_once(self):
		"""Every whitelisted return arrives inside `message`; callers should
		not each have to remember that."""
		self.assertEqual(Result(ok=True, data={"message": {"app": "server"}}).message, {"app": "server"})

	def test_a_bare_dict_survives_unwrapping(self):
		self.assertEqual(Result(ok=True, data={"app": "server"}).message, {"app": "server"})

	def test_a_failed_result_has_an_empty_message_rather_than_none(self):
		self.assertEqual(Result(ok=False, error="boom").message, {})


class TestCredentialsAreSentAsAHeader(unittest.TestCase):
	def test_the_token_is_a_header_not_a_query_parameter(self):
		"""A secret in the query string ends up in the remote's access log."""
		headers = RemoteServer("https://x", "KEY", "SECRET")._headers()
		self.assertEqual(headers["Authorization"], "token KEY:SECRET")

	def test_tls_verification_is_on_unless_asked_otherwise(self):
		self.assertIsNone(RemoteServer("https://x", "k", "s")._context())
		self.assertIsNotNone(RemoteServer("https://x", "k", "s", verify_tls=False)._context())


class TestTheTransferStopsOnSizeNotOnTheResponse(unittest.TestCase):
	"""The heart of it. The client is told how many bytes to expect."""

	def _server(self, chunks):
		"""A RemoteServer whose `_slice` returns canned windows."""
		server = RemoteServer("https://x", "k", "s")
		server._calls = []

		def fake_slice(url, start):
			server._calls.append(start)
			return chunks.pop(0) if chunks else b""

		server._slice = fake_slice
		return server

	def test_it_keeps_asking_until_it_has_every_byte(self):
		server = self._server([b"a" * 100, b"b" * 100, b"c" * 50])
		with tempfile.TemporaryDirectory() as tmp:
			target = os.path.join(tmp, "f.gz")
			progress = server.download("m", {}, target, expected_size=250)
			self.assertEqual(progress.received, 250)
			self.assertEqual(os.path.getsize(target), 250)
		self.assertEqual(server._calls, [0, 100, 200], "each window continues from the last")

	def test_a_short_transfer_is_refused_rather_than_returned(self):
		"""The whole point: a truncated backup must fail HERE, loudly, not at
		restore time on the machine being migrated to."""
		server = self._server([b"a" * 100])
		with tempfile.TemporaryDirectory() as tmp:
			with self.assertRaises(Exception) as caught:
				server.download("m", {}, os.path.join(tmp, "f.gz"), expected_size=250)
		self.assertIn("incomplete", str(caught.exception))

	def test_it_resumes_from_what_is_already_on_disk(self):
		server = self._server([b"c" * 50])
		with tempfile.TemporaryDirectory() as tmp:
			target = os.path.join(tmp, "f.gz")
			with open(target, "wb") as handle:
				handle.write(b"x" * 200)
			progress = server.download("m", {}, target, expected_size=250)
		self.assertEqual(progress.resumed_from, 200)
		self.assertEqual(progress.received, 250)
		self.assertEqual(server._calls, [200], "it asked only for what was missing")

	def test_a_file_longer_than_the_source_is_discarded_not_resumed(self):
		"""Leftover from a different, larger backup under the same name.
		Appending to it would build nonsense."""
		server = self._server([b"a" * 250])
		with tempfile.TemporaryDirectory() as tmp:
			target = os.path.join(tmp, "f.gz")
			with open(target, "wb") as handle:
				handle.write(b"x" * 900)
			progress = server.download("m", {}, target, expected_size=250)
		self.assertEqual(progress.resumed_from, 0)
		self.assertEqual(server._calls, [0])

	def test_an_empty_window_ends_a_transfer_of_unknown_size(self):
		"""Without an expected size there is no other stop signal."""
		server = self._server([b"a" * 100])
		with tempfile.TemporaryDirectory() as tmp:
			progress = server.download("m", {}, os.path.join(tmp, "f.gz"))
		self.assertEqual(progress.received, 100)

	def test_nothing_left_to_send_is_not_an_error(self):
		"""416 means the caller already has the file."""
		server = self._server([])
		with tempfile.TemporaryDirectory() as tmp:
			target = os.path.join(tmp, "f.gz")
			with open(target, "wb") as handle:
				handle.write(b"x" * 250)
			progress = server.download("m", {}, target, expected_size=250)
		self.assertEqual(progress.received, 250)
		self.assertEqual(server._calls, [], "it did not ask for anything")


class TestProgress(unittest.TestCase):
	def test_percent_is_reported_against_the_total(self):
		self.assertEqual(Progress(received=50, total=200).percent, 25.0)

	def test_an_unknown_total_does_not_divide_by_zero(self):
		self.assertEqual(Progress(received=50, total=0).percent, 0.0)
