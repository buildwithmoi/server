# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""GitHub client tests.

The transport is stubbed throughout, and that is not only for speed: GitHub
allows sixty unauthenticated requests an hour, and a suite that spent them would
fail for everyone else on the machine for the rest of the hour. Exercising this
against the real API once, by hand, is enough; the behaviour under every
response shape belongs here.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from contextlib import contextmanager
from typing import ClassVar
from unittest import mock

from server.bench import github


@contextmanager
def stub_pages(*pages):
	"""Serve each page in turn, so pagination is genuinely exercised."""
	payloads = [json.dumps(p).encode("utf-8") for p in pages]
	calls = {"n": 0}

	def _open(request, timeout=None):
		index = min(calls["n"], len(payloads) - 1)
		calls["n"] += 1

		class _Response(io.BytesIO):
			headers: ClassVar[dict] = {}

			def __enter__(self):
				return self

			def __exit__(self, *exc):
				return False

		return _Response(payloads[index])

	with mock.patch.object(github.urllib.request, "urlopen", side_effect=_open):
		yield calls


@contextmanager
def stub_http_error(code: int, headers: dict | None = None):
	# HTTPError holds an open file object and warns when the GC finds it still
	# open, so it is closed explicitly rather than littering the suite output.
	body = io.BytesIO(b"{}")
	error = urllib.error.HTTPError("https://api.github.com/x", code, "err", headers or {}, body)
	try:
		with mock.patch.object(github.urllib.request, "urlopen", side_effect=error):
			yield
	finally:
		error.close()
		body.close()


REPO = {
	"name": "gh_erp",
	"default_branch": "main",
	"private": True,
	"archived": False,
	"description": "ERP overrides",
	"pushed_at": "2026-08-24T13:32:02Z",
	"ssh_url": "git@github.com:Org/gh_erp.git",
}


class TestRepoMapping(unittest.TestCase):
	def test_fields_are_mapped(self):
		with stub_pages([REPO]):
			repos = github.list_repos("Org", "Organisation", token="t")
		self.assertEqual(len(repos), 1)
		repo = repos[0]
		self.assertEqual(repo["repo_name"], "gh_erp")
		self.assertEqual(repo["default_branch"], "main")
		self.assertEqual(repo["is_private"], 1)
		self.assertEqual(repo["is_archived"], 0)

	def test_timestamp_is_storable_in_a_datetime_column(self):
		"""GitHub sends `...T13:32:02Z`; MariaDB DATETIME rejects the offset.

		The same class of failure the SSH ingest hit, so it is stripped at this
		boundary too rather than blowing up on insert.
		"""
		with stub_pages([REPO]):
			repo = github.list_repos("Org", "Organisation")[0]
		self.assertEqual(repo["pushed_at"], "2026-08-24 13:32:02")
		self.assertNotIn("Z", repo["pushed_at"])
		self.assertNotIn("T", repo["pushed_at"])

	def test_repos_without_a_name_are_dropped(self):
		with stub_pages([REPO, {"default_branch": "main"}]):
			self.assertEqual(len(github.list_repos("Org", "Organisation")), 1)

	def test_organisation_and_user_hit_different_endpoints(self):
		seen = []

		def _open(request, timeout=None):
			seen.append(request.full_url)

			class _R(io.BytesIO):
				headers: ClassVar[dict] = {}

				def __enter__(self):
					return self

				def __exit__(self, *exc):
					return False

			return _R(b"[]")

		with mock.patch.object(github.urllib.request, "urlopen", side_effect=_open):
			github.list_repos("Org", "Organisation")
			github.list_repos("someone", "User")

		self.assertIn("/orgs/Org/repos", seen[0])
		self.assertIn("/users/someone/repos", seen[1])


class TestPagination(unittest.TestCase):
	def test_stops_when_a_short_page_arrives(self):
		full = [dict(REPO, name=f"r{i}") for i in range(github.PER_PAGE)]
		with stub_pages(full, [dict(REPO, name="last")]) as calls:
			repos = github.list_repos("Org", "Organisation")
		self.assertEqual(len(repos), github.PER_PAGE + 1)
		self.assertEqual(calls["n"], 2, "a short page means stop, not keep asking")

	def test_page_cap_is_honoured(self):
		full = [dict(REPO, name=f"r{i}") for i in range(github.PER_PAGE)]
		with stub_pages(full) as calls:
			github.list_repos("Org", "Organisation")
		self.assertEqual(calls["n"], github.MAX_PAGES)


class TestBranches(unittest.TestCase):
	def test_returns_branches_and_a_truncation_flag(self):
		with stub_pages([{"name": "develop", "protected": True}, {"name": "main"}]):
			branches, truncated = github.list_branches("Org", "repo")
		self.assertEqual([b["name"] for b in branches], ["develop", "main"])
		self.assertTrue(branches[0]["protected"])
		self.assertFalse(truncated)

	def test_truncation_is_reported_rather_than_hidden(self):
		"""A silently partial list makes a branch that exists look missing.

		erpnext really does carry over six hundred branches, so this is not a
		hypothetical.
		"""
		full = [{"name": f"b{i}"} for i in range(github.PER_PAGE)]
		with stub_pages(full):
			branches, truncated = github.list_branches("Org", "repo")
		self.assertTrue(truncated)
		self.assertEqual(len(branches), github.PER_PAGE * github.MAX_PAGES)

	def test_callers_must_unpack_two_values(self):
		"""Regression: the API layer returned the tuple whole for a while.

		The browser then received `[[...], false]` as its branch list, showed
		"2 branches available", and every branch was unselectable.
		"""
		with stub_pages([{"name": "main"}]):
			result = github.list_branches("Org", "repo")
		self.assertIsInstance(result, tuple)
		self.assertEqual(len(result), 2)
		self.assertIsInstance(result[0], list)
		self.assertIsInstance(result[1], bool)


class TestErrorMessages(unittest.TestCase):
	"""Status codes are useless to an operator; these name what to change."""

	def test_401_points_at_the_token(self):
		with stub_http_error(401), self.assertRaises(github.GitHubError) as ctx:
			github.list_repos("Org", "Organisation", token="bad")
		self.assertIn("token", str(ctx.exception).lower())

	def test_rate_limit_explains_the_remedy(self):
		with (
			stub_http_error(403, {"X-RateLimit-Remaining": "0"}),
			self.assertRaises(github.GitHubError) as ctx,
		):
			github.list_repos("Org", "Organisation")
		message = str(ctx.exception)
		self.assertIn("rate limit", message.lower())
		self.assertIn("60", message, "the unauthenticated limit is the actionable number")

	def test_403_with_quota_left_blames_scope_not_rate(self):
		with (
			stub_http_error(403, {"X-RateLimit-Remaining": "4999"}),
			self.assertRaises(github.GitHubError) as ctx,
		):
			github.list_repos("Org", "Organisation", token="t")
		self.assertIn("scope", str(ctx.exception).lower())

	def test_404_on_a_repo_lookup_blames_the_repo_not_the_account(self):
		"""Reporting the account for a branch lookup sends someone off checking
		a setting that was right all along — which is what happened first time."""
		with stub_http_error(404), self.assertRaises(github.GitHubError) as ctx:
			github.list_branches("Org", "no-such-repo", token="t")
		self.assertIn("repository", str(ctx.exception).lower())

	def test_404_on_an_account_lookup_blames_the_account(self):
		with stub_http_error(404), self.assertRaises(github.GitHubError) as ctx:
			github.list_repos("no-such-org", "Organisation", token="t")
		self.assertIn("account", str(ctx.exception).lower())

	def test_network_failure_is_wrapped(self):
		with (
			mock.patch.object(
				github.urllib.request, "urlopen", side_effect=urllib.error.URLError("no route")
			),
			self.assertRaises(github.GitHubError) as ctx,
		):
			github.list_repos("Org", "Organisation")
		self.assertIn("api.github.com", str(ctx.exception))

	def test_empty_account_is_refused_before_any_request(self):
		with mock.patch.object(github.urllib.request, "urlopen") as urlopen:
			with self.assertRaises(github.GitHubError):
				github.list_repos("", "Organisation")
		urlopen.assert_not_called()


if __name__ == "__main__":
	unittest.main()
