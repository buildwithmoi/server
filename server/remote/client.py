# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Talking to another server running this same app.

THE SHAPE, AND WHY IT IS THIS ONE. The browser only ever talks to the server
you logged into. When you switch to another, that server forwards the call
using credentials it holds, and the answer comes back the same way. The
alternative — pointing the browser straight at the remote — needs CORS enabled
on every machine and puts an API secret into JavaScript, where anything running
on the page can read it.

So this module is the outbound half: one client, one `call`, and a download
that can resume. `api.call_remote` is the guarded entry point in front of it.

WHAT IT REFUSES TO DO. It never dispatches a method name it was handed without
that name having been checked against an allow-list first — that check lives in
`api.py` where the request arrives, because a proxy that forwards anything is
just a remote shell with extra steps, and this app already has one of those
with a confirmation box in front of it.

RESUME IS NOT OPTIONAL FOR THE FILES. A site backup is measured in gigabytes,
and moving one between two servers on ordinary connections will be interrupted.
`download` records what it has and asks for the rest with a Range header, so an
interruption costs the seconds since the last chunk rather than the transfer.

Frappe-free: it takes a base URL and a key pair, and returns results. The
credentials are read from the doctype by the caller.
"""

from __future__ import annotations

import json
import re
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from server.domains.http import USER_AGENT, HttpError

#: Long enough for a remote to take a backup of a large site before answering,
#: short enough that an unreachable host does not hold a worker all afternoon.
CALL_TIMEOUT = 180

#: One read from the socket. Large enough that a gigabyte does not mean a
#: hundred thousand syscalls, small enough to report progress that means
#: something.
CHUNK = 4 * 1024 * 1024

#: How long to wait for the first byte of a download.
DOWNLOAD_TIMEOUT = 120


@dataclass(frozen=True)
class Result:
	"""What a remote call returned. `error` set means it did not work.

	Never raises, for the same reason the geo resolvers and the DNS providers
	never raise: a server being down is an ordinary Tuesday, and a detector or
	a dialog that explodes because another machine is rebooting is worse than
	one that reports it.
	"""

	ok: bool
	data: dict | list | None = None
	error: str = ""
	status: int = 0

	@property
	def message(self) -> dict:
		"""frappe wraps whitelisted returns in `message`; unwrap it once here."""
		if isinstance(self.data, dict) and "message" in self.data:
			return self.data["message"]
		return self.data if isinstance(self.data, dict) else {}


@dataclass(frozen=True)
class Progress:
	received: int = 0
	total: int = 0
	resumed_from: int = 0

	@property
	def percent(self) -> float:
		return round(self.received * 100 / self.total, 1) if self.total else 0.0


class RemoteServer:
	"""One other machine running this app."""

	def __init__(self, base_url: str, api_key: str, api_secret: str, verify_tls: bool = True):
		self.base_url = (base_url or "").rstrip("/")
		self.api_key = api_key or ""
		self.api_secret = api_secret or ""
		self.verify_tls = verify_tls

	# ------------------------------------------------------------------

	def _headers(self) -> dict:
		return {
			# frappe's own token scheme. Sent as a header rather than in the
			# query string so it does not end up in the remote's access log.
			"Authorization": f"token {self.api_key}:{self.api_secret}",
			"User-Agent": USER_AGENT,
			"Accept": "application/json",
		}

	def _context(self):
		"""TLS verification, off only when explicitly asked.

		A self-signed certificate is normal on a machine that has not been
		given a domain yet, and refusing to talk to it would make this feature
		unusable exactly when it is most useful — moving sites onto a server
		that is not finished. It is a per-server switch with a warning on it,
		never a default.
		"""
		if self.verify_tls:
			return None
		import ssl as _ssl

		context = _ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = _ssl.CERT_NONE
		return context

	# ------------------------------------------------------------------

	def call(self, method: str, args: dict | None = None, timeout: int = CALL_TIMEOUT) -> Result:
		"""Invoke one whitelisted method on the remote and return its answer."""
		url = f"{self.base_url}/api/method/{method}"
		body = json.dumps(args or {}).encode()
		request = urllib.request.Request(url, data=body, method="POST")
		for key, value in {**self._headers(), "Content-Type": "application/json"}.items():
			request.add_header(key, value)

		try:
			with urllib.request.urlopen(  # noqa: S310
				request, timeout=timeout, context=self._context()
			) as response:
				raw = response.read().decode("utf-8", "replace")
				return Result(ok=True, data=json.loads(raw) if raw.strip() else {}, status=response.status)
		except urllib.error.HTTPError as exc:
			detail = _explain_remote(exc)
			return Result(ok=False, error=detail, status=exc.code)
		except (urllib.error.URLError, OSError) as exc:
			return Result(ok=False, error=f"{self.base_url} is not answering: {exc}")
		except (ValueError, json.JSONDecodeError) as exc:
			return Result(ok=False, error=f"{self.base_url} returned something that is not JSON: {exc}")

	def verify(self) -> Result:
		"""Is this a reachable server running this app, and do the keys work?

		Deliberately calls this app's OWN endpoint rather than frappe's ping.
		A frappe site that answers `ping` may not have this app installed at
		all, and "connected" would then be a lie the operator only discovers
		when a restore fails halfway.
		"""
		result = self.call("server.api.server_identity", {}, timeout=45)
		if not result.ok:
			return result

		identity = result.message
		if not identity.get("app"):
			return Result(
				ok=False,
				error=(
					f"{self.base_url} answered, but it is not running this app — so there is "
					"nothing here to switch to. Install `server` on it first."
				),
			)
		return Result(ok=True, data=identity)

	# ------------------------------------------------------------------

	def download(
		self,
		method: str,
		args: dict,
		destination: str,
		expected_size: int = 0,
		on_progress=None,
	) -> Progress:
		"""Pull a file down in bounded slices, resuming whatever is on disk.

		THE CLIENT DRIVES THE CHUNKING and the client decides when it is done,
		from `expected_size` — which it already has, because the same metadata
		call that named the backup gave its size.

		Both halves of that are forced by how frappe answers. It builds a
		binary response from a filename and a body, discarding any status code
		or header the endpoint set — so there is no `Content-Range` to read and
		no 206 to distinguish a slice from a whole file. A client that trusted
		`Content-Length` would take the first chunk for the entire backup and
		write a truncated archive that only fails at restore, hours later, on
		the machine being migrated to. Asking for bounded windows and counting
		to a known total is what makes that impossible.

		Raises `HttpError` rather than returning a Result: the caller is a job
		that must fail loudly and leave a partial file it can resume from, not
		a dialog deciding what to render.
		"""
		received = os.path.getsize(destination) if os.path.exists(destination) else 0
		resumed_from = received

		if expected_size and received > expected_size:
			# More on disk than the source has: a leftover from a different,
			# larger backup under the same name. Appending to it would build
			# nonsense, so it is discarded rather than resumed.
			os.remove(destination)
			received = resumed_from = 0

		query = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in args.items())
		url = f"{self.base_url}/api/method/{method}?{query}"

		while True:
			if expected_size and received >= expected_size:
				break

			body = self._slice(url, received)
			if not body:
				# An empty body is how the source says "nothing left". Without
				# an expected size that is the only stop signal there is.
				break

			with open(destination, "ab") as handle:
				handle.write(body)
			received += len(body)
			if on_progress:
				on_progress(Progress(received, expected_size, resumed_from))

		if expected_size and received != expected_size:
			raise HttpError(
				f"Transfer finished at {received:,} bytes but the source said {expected_size:,}. "
				"The file on disk is incomplete and has not been used."
			)

		return Progress(received=received, total=expected_size or received, resumed_from=resumed_from)

	def _slice(self, url: str, start: int) -> bytes:
		"""One window, requested explicitly so neither side buffers a backup."""
		request = urllib.request.Request(url)
		for key, value in self._headers().items():
			request.add_header(key, value)
		request.add_header("Range", f"bytes={start}-{start + CHUNK - 1}")

		try:
			with urllib.request.urlopen(  # noqa: S310
				request, timeout=DOWNLOAD_TIMEOUT, context=self._context()
			) as response:
				return response.read()
		except urllib.error.HTTPError as exc:
			if exc.code == 416:
				return b""
			raise HttpError(_explain_remote(exc)) from exc
		except (urllib.error.URLError, OSError) as exc:
			raise HttpError(f"{self.base_url} is not answering: {exc}") from exc


def _content_total(response, already: int) -> int:
	"""Total size of the whole file, whether the answer was 200 or 206."""
	content_range = response.headers.get("Content-Range") or ""
	if "/" in content_range:
		try:
			return int(content_range.rsplit("/", 1)[1])
		except ValueError:
			pass
	try:
		return int(response.headers.get("Content-Length") or 0) + already
	except ValueError:
		return 0


def _explain_remote(exc) -> str:
	"""Turn a remote HTTP failure into something worth showing an operator."""
	try:
		body = exc.read().decode("utf-8", "replace")[:600]
	except Exception:  # noqa: BLE001
		body = ""

	said = _remote_said(body)

	# 401 and 403 are DIFFERENT ANSWERS and were reported as the same one.
	#
	# 401 is "I do not know you". 403 is "I know exactly who you are and the
	# answer is no" — which is what frappe returns for every PermissionError,
	# including the one raised when Allow App Installs is switched off. A
	# migration was stopped by that checkbox and the message sent its operator
	# to check API keys that were working perfectly.
	if exc.code == 401:
		return (
			"The remote did not accept the API key and secret. Check both, and that the user "
			"they belong to still exists there."
			+ (f" It said: {said}" if said else "")
		)
	if exc.code == 403:
		return (
			# What the remote itself said comes FIRST. It is the only part of
			# this that knows which of several refusals it was.
			(f"The remote refused: {said}" if said else "The remote refused the request.")
			+ " The credentials were accepted — this is a permission, not a login. Check that "
			"the user they belong to is a System Manager there, and that Allow App Installs is "
			"on in its Server Settings if this was going to run a command."
		)
	if exc.code == 404:
		return "The remote does not have that endpoint — it may be running an older version of this app."

	return f"HTTP {exc.code}{': ' + said[:300] if said else ''}"


def _remote_said(body: str) -> str:
	"""frappe's own message for a failure, dug out of whichever field it used.

	It puts the useful sentence in `_server_messages` — a JSON string holding a
	list of JSON strings — and leaves `exception` as a traceback repr. Reading
	only `exception` gave "frappe.exceptions.PermissionError" for a refusal
	whose actual text named the setting to turn on.
	"""
	try:
		payload = json.loads(body)
	except Exception:  # noqa: BLE001
		return body.strip()[:300]

	messages = payload.get("_server_messages")
	if messages:
		try:
			for entry in json.loads(messages):
				parsed = json.loads(entry) if isinstance(entry, str) else entry
				text = (parsed.get("message") if isinstance(parsed, dict) else str(parsed)) or ""
				# Frappe writes these as HTML.
				text = re.sub(r"<[^>]+>", " ", text)
				text = " ".join(text.split())
				if text:
					return text[:300]
		except Exception:  # noqa: BLE001
			pass

	for field in ("message", "exception", "exc_type"):
		value = payload.get(field)
		if value:
			return " ".join(str(value).split())[:300]
	return ""
