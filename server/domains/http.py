# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A small JSON-over-HTTPS helper for the DNS providers.

Stdlib `urllib` rather than `requests`, and no provider SDK. Both providers
publish official Python SDKs and both would drag in a dependency tree to do
four HTTP calls this file does in forty lines — and an SDK that hides the wire
format makes the one thing this app must be careful about, the exact body sent
to a zone-replacing endpoint, harder to see rather than easier.

TWO THINGS MEASURED ON THIS BOX THAT WOULD OTHERWISE COST AN HOUR EACH.

  The User-Agent is not optional. Hostinger's API sits behind Cloudflare, which
  answers urllib's default `Python-urllib/3.14` with **403 Forbidden** — a
  status that reads exactly like a rejected token, on the one call whose whole
  job is to tell you whether your token works. With any ordinary User-Agent the
  same request returns 200. Verified directly against the live host.

  The error body is where the reason lives. Both providers put a usable
  explanation in the response body of a 4xx, and `urllib` raises `HTTPError`
  with that body still readable on the exception. Discarding it and reporting
  the status alone turns "this token lacks the domains.dns:update scope" into
  "403".

THE TOKEN IS NEVER IN A RETURNED STRING. It is a header on the way out and it
appears nowhere in a `Result`, because those are shown in the interface, stored
on a document and — for anything raised as a finding — forwarded off the box.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

#: Cloudflare rejects urllib's default. Naming the app is also the polite thing
#: to do: a provider looking at their logs can see what is calling them.
USER_AGENT = "carbonite-server-app/1.0 (+frappe; dns-provider-client)"

#: Long enough for a registrar having a slow morning; short enough that a
#: provisioning job does not sit on a dead endpoint for minutes.
TIMEOUT = 30

#: Bodies above this are truncated before being shown. A provider that returns
#: an HTML error page instead of JSON should not put a page of markup into a
#: document field.
MAX_DETAIL = 600


class HttpError(Exception):
	"""A request that did not succeed, with the provider's own words attached."""

	def __init__(self, message: str, status: int = 0, body: str = ""):
		super().__init__(message)
		self.status = status
		self.body = body


def request(
	method: str,
	url: str,
	token: str = "",
	payload: dict | list | None = None,
	headers: dict | None = None,
) -> dict | list:
	"""One JSON call. Raises `HttpError`; the providers turn that into a Result.

	Raising here and catching one level up is deliberate: the transport has no
	opinion about what a failure means, and the provider does — a 404 from
	`list_records` means "no such zone", while a 404 from `delete_record` means
	the record was already gone, which is a success.
	"""
	body = None
	sent = {"User-Agent": USER_AGENT, "Accept": "application/json"}
	if payload is not None:
		body = json.dumps(payload).encode()
		sent["Content-Type"] = "application/json"
	if token:
		sent["Authorization"] = f"Bearer {token}"
	sent.update(headers or {})

	req = urllib.request.Request(url, data=body, headers=sent, method=method.upper())

	try:
		with urllib.request.urlopen(req, timeout=TIMEOUT) as response:  # noqa: S310
			raw = response.read().decode("utf-8", "replace")
	except urllib.error.HTTPError as exc:
		detail = ""
		try:
			detail = exc.read().decode("utf-8", "replace")[:MAX_DETAIL]
		except Exception:  # noqa: BLE001
			detail = ""
		raise HttpError(_explain(exc.code, detail), status=exc.code, body=detail) from exc
	except urllib.error.URLError as exc:
		raise HttpError(f"Could not reach {_host(url)}: {exc.reason}") from exc
	except (OSError, ValueError) as exc:
		raise HttpError(f"Could not reach {_host(url)}: {exc}") from exc

	if not raw.strip():
		# A 204 from a delete. Callers check `ok`, not the body.
		return {}

	try:
		return json.loads(raw)
	except ValueError as exc:
		raise HttpError(
			f"{_host(url)} replied with something that is not JSON.", body=raw[:MAX_DETAIL]
		) from exc


def _host(url: str) -> str:
	from urllib.parse import urlparse

	return urlparse(url).netloc or url


def _explain(status: int, body: str) -> str:
	"""Turn a status into the sentence the operator needs.

	The body usually says more than the status, so it is appended rather than
	replaced — but the status alone has to be actionable, because a provider
	that returns an empty 403 is exactly the case where nobody can guess.
	"""
	known = {
		401: "The credential was rejected. Check the token, and that it has not been revoked.",
		403: (
			"The credential was accepted but is not allowed to do this. Usually a missing "
			"scope — or, on a provider behind a bot filter, a request it did not like."
		),
		404: "Not found. The zone may not be in this account.",
		409: "Conflict — the record may already exist with different content.",
		422: "The provider refused the record as invalid.",
		429: "Rate limited. Wait and try again.",
	}
	message = known.get(status) or f"The provider returned HTTP {status}."
	trimmed = " ".join((body or "").split())[:200]
	return f"{message} {trimmed}".strip() if trimmed else message
