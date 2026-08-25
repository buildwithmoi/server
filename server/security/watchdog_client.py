#!/usr/bin/env python3
# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A reference watcher, to run on a DIFFERENT machine from the one it watches.

Standard library only, no frappe, no install. Copy this file to another host,
put the watchdog token in the environment, and run it from cron:

    SERVER_WATCHDOG_URL=https://example.com/api/method/server.api.security_heartbeat
    SERVER_WATCHDOG_TOKEN=...
    */10 * * * * /usr/bin/python3 /opt/watchdog.py || mail -s "watchdog" you@example.com

WHY THIS EXISTS AS CODE RATHER THAN AS DOCUMENTATION. Everything else this app
does runs on the host it is watching, and a process that has been stopped
cannot notice that it has been stopped. The heartbeat endpoint is the answer,
but only if something actually polls it — and "point your monitoring at this
URL" is the kind of instruction that gets read, agreed with, and not done.

WHAT IT CHECKS, in the order that matters:

  The signature.       Anything that can intercept the request can return a
                       healthy payload forever. An unsigned check watches the
                       network, not the host.
  Freshness.           A captured reply is a valid reply. The signed timestamp
                       must be recent or the answer is somebody's recording.
  The sequence.        It only ever climbs. Going BACKWARDS means the database
                       was replaced with an older copy — which is what
                       restoring a pre-intrusion backup looks like from here.
  The chain head.      For a sequence already seen, the head must be the same
                       value. A different one means the finding history was
                       rewritten.
  The fingerprint.     Changing with no deploy behind it means the detectors
                       themselves were edited.
  Then the findings.   Overdue detectors, then open Criticals.

State is one small JSON file, because the last two checks are comparisons
against what this watcher saw before.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

STATE_FILE = os.environ.get("SERVER_WATCHDOG_STATE", os.path.expanduser("~/.server-watchdog.json"))
TIMEOUT = 20
#: A reply older than this is a recording, not an answer.
MAX_AGE_SECONDS = 600


def fetch(url: str, token: str) -> dict:
	request = urllib.request.Request(f"{url}?token={urllib.parse.quote(token)}")
	with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
		body = json.loads(response.read().decode())
	# frappe wraps whitelisted return values in {"message": ...}
	return body.get("message", body)


def verify_signature(payload: dict, token: str) -> bool:
	"""Recompute the HMAC the way the host computed it.

	Constant-time comparison: a signature checked with `==` leaks its own
	prefix to whoever is timing the watcher.
	"""
	received = payload.get("signature") or ""
	unsigned = {k: v for k, v in payload.items() if k != "signature"}
	expected = hmac.new(
		token.encode(),
		json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
		hashlib.sha256,
	).hexdigest()
	return hmac.compare_digest(received, expected)


def load_state() -> dict:
	try:
		with open(STATE_FILE) as handle:
			return json.load(handle)
	except (OSError, ValueError):
		return {}


def save_state(state: dict) -> None:
	try:
		with open(STATE_FILE, "w") as handle:
			json.dump(state, handle)
	except OSError as exc:
		print(f"warning: could not write {STATE_FILE}: {exc}", file=sys.stderr)


def check(payload: dict, state: dict, token: str) -> list[str]:
	"""Every problem worth waking someone for, worst first."""
	problems: list[str] = []

	if not verify_signature(payload, token):
		# Nothing below can be trusted after this, so it is the only finding.
		return ["SIGNATURE INVALID — this reply did not come from the host, or the token is wrong"]

	stamp = payload.get("time") or ""
	try:
		# The host signs a naive UTC timestamp; compare in UTC explicitly
		# rather than via utcnow(), which is deprecated from 3.12.
		signed = datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc)
		age = datetime.now(timezone.utc) - signed
		if age > timedelta(seconds=MAX_AGE_SECONDS):
			problems.append(f"STALE REPLY — signed {age} ago; this may be a replayed capture")
	except (TypeError, ValueError):
		problems.append(f"UNREADABLE TIMESTAMP — {stamp!r}")

	sequence = int(payload.get("sequence_total") or 0)
	last_sequence = int(state.get("sequence_total") or 0)
	if sequence < last_sequence:
		problems.append(
			f"SEQUENCE WENT BACKWARDS — {last_sequence} then {sequence}. "
			"The database may have been replaced with an older copy."
		)
	elif sequence == last_sequence and last_sequence:
		problems.append(f"SEQUENCE HAS NOT MOVED — still {sequence}; the detectors may have stopped")

	chain_sequence = int(payload.get("chain_sequence") or 0)
	head = payload.get("chain_head") or ""
	if state.get("chain_sequence") and chain_sequence < int(state["chain_sequence"]):
		problems.append("FINDING HISTORY SHRANK — findings were deleted")
	elif (
		state.get("chain_sequence")
		and chain_sequence == int(state["chain_sequence"])
		and state.get("chain_head")
		and head != state["chain_head"]
	):
		problems.append("FINDING HISTORY REWRITTEN — same length, different contents")

	fingerprint = payload.get("code_fingerprint") or ""
	if state.get("code_fingerprint") and fingerprint and fingerprint != state["code_fingerprint"]:
		problems.append(
			f"MONITORING CODE CHANGED — {state['code_fingerprint'][:12]} then {fingerprint[:12]}. "
			"Expected after a deploy; otherwise the detectors themselves were edited."
		)

	for detector in payload.get("overdue") or []:
		problems.append(
			f"DETECTOR STOPPED — {detector.get('source')} is {int(detector.get('seconds_late', 0)) // 60} "
			f"minutes late"
		)

	if payload.get("open_critical"):
		problems.append(f"{payload['open_critical']} unacknowledged Critical finding(s)")

	return problems


def main() -> int:
	url = os.environ.get("SERVER_WATCHDOG_URL", "")
	token = os.environ.get("SERVER_WATCHDOG_TOKEN", "")
	if not url or not token:
		print("set SERVER_WATCHDOG_URL and SERVER_WATCHDOG_TOKEN", file=sys.stderr)
		return 2

	try:
		payload = fetch(url, token)
	except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as exc:
		# Unreachable is itself the alarm: a host that has stopped answering is
		# the case this whole mechanism exists for.
		print(f"UNREACHABLE — {type(exc).__name__}: {exc}", file=sys.stderr)
		return 1

	state = load_state()
	problems = check(payload, state, token)

	if verify_signature(payload, token):
		save_state(
			{
				"sequence_total": payload.get("sequence_total"),
				"chain_sequence": payload.get("chain_sequence"),
				"chain_head": payload.get("chain_head"),
				"code_fingerprint": payload.get("code_fingerprint"),
			}
		)

	if problems:
		print(f"{payload.get('host', 'host')}:", file=sys.stderr)
		for problem in problems:
			print(f"  {problem}", file=sys.stderr)
		return 1

	print(f"{payload.get('host', 'host')}: ok, sequence {payload.get('sequence_total')}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
