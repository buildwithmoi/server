# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading authentication records out of systemd-journald.

WHY SHELL OUT TO `journalctl` RATHER THAN BIND THE LIBRARY. The obvious
alternative is python-systemd, but the distro package is built for the system
python (3.12 here) and the bench runs a uv-managed python 3.14 that cannot
import it. Building `systemd-python` into the bench env would add a compiler and
libsystemd-dev to the deployment requirements of a monitoring app. `journalctl`
is already installed, needs no privileges beyond group membership, and its JSON
output is a stable documented interface — so it wins on every axis that matters.

WHY THIS IS THE PREFERRED SOURCE OVER auth.log. The journal gives three things
the text file cannot: a resumable opaque cursor, the kernel's `_AUDIT_SESSION`
(the only reliable link between a login and the sudo commands it ran), and
`_BOOT_ID` (which stops pid reuse across a reboot merging two logins).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterator

#: Both facilities are required, and this is NOT belt-and-braces.
#: Verified by counting 200 records on the dev box: sudo, CRON, login and
#: polkitd arrive on authpriv (10), while systemd-logind arrives on auth (4).
#: OpenSSH's default `SyslogFacility AUTH` also puts sshd on 4. Matching only
#: one facility silently loses half the picture.
AUTH_FACILITIES = ("auth", "authpriv")

#: The exact string journalctl writes to stderr when the stored cursor has been
#: rotated out of the journal. Verified empirically; it exits 1 in that case.
_CURSOR_LOST_MARKER = "Failed to seek to cursor"

JOURNALCTL = "journalctl"


class JournalError(Exception):
	"""journalctl could not be run, or failed for a reason we do not handle."""


class JournalUnavailableError(JournalError):
	"""journalctl is missing, or this user cannot read the system journal."""


class CursorLostError(JournalError):
	"""The stored cursor is no longer in the journal; the caller must bootstrap."""


def is_available() -> bool:
	"""Can we run journalctl at all?"""
	if not shutil.which(JOURNALCTL):
		return False
	try:
		result = subprocess.run(
			[JOURNALCTL, "-n", "0", "--no-pager", "--quiet"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			timeout=15,
			check=False,
		)
	except OSError, subprocess.SubprocessError:
		return False
	return result.returncode == 0


def can_read_system_records() -> bool:
	"""Can we see records belonging to OTHER users, specifically root?

	This is the check that matters, and it is not the same as "journalctl runs".
	Without the `adm` (or `systemd-journal`) group, journalctl succeeds but
	returns only this user's own records — so sshd and sudo events simply are
	not there. That failure looks exactly like "a quiet server with no logins",
	which is the most dangerous way for a security tool to fail.
	"""
	try:
		result = subprocess.run(
			[JOURNALCTL, "--no-pager", "-o", "json", "-n", "50", "_UID=0"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=20,
			check=False,
		)
	except OSError, subprocess.SubprocessError:
		return False
	if result.returncode != 0:
		return False
	return any(line.strip() for line in result.stdout.splitlines())


def build_argv(cursor: str | None = None, since_hours: int = 24) -> list[str]:
	"""Assemble the journalctl command line.

	NOTE THE ABSENCE OF `-n/--lines`. It is tempting to cap the read there, but
	`-n` means "the most recent N records", not "the next N after the cursor".
	Combining it with `--after-cursor` on a backlog of 50 000 events would
	silently skip 45 000 of them — a data-loss bug that leaves no trace. The cap
	is applied in Python instead, by stopping the iterator early.
	"""
	argv = [JOURNALCTL, "--output=json", "--no-pager"]
	for facility in AUTH_FACILITIES:
		argv.append(f"--facility={facility}")
	if cursor:
		argv.append(f"--after-cursor={cursor}")
	else:
		argv.append(f"--since=-{int(since_hours)}hours")
	return argv


def read_records(
	cursor: str | None = None,
	since_hours: int = 24,
	limit: int = 5000,
) -> Iterator[dict]:
	"""Yield journal records as dicts, oldest first, at most `limit` of them.

	Raises `CursorLostError` if the stored cursor has been rotated away, and
	`JournalUnavailableError` if journalctl cannot run at all.

	stderr goes to a temporary FILE rather than a pipe on purpose: with two
	pipes and a single reader, a large stderr could fill its buffer and deadlock
	against us draining stdout.
	"""
	argv = build_argv(cursor=cursor, since_hours=since_hours)

	with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errfile:
		try:
			proc = subprocess.Popen(
				argv,
				stdin=subprocess.DEVNULL,
				stdout=subprocess.PIPE,
				stderr=errfile,
				text=True,
				bufsize=1,
			)
		except OSError as exc:
			raise JournalUnavailableError(f"could not run journalctl: {exc}") from exc

		emitted = 0
		terminated_early = False
		try:
			for line in proc.stdout:
				line = line.strip()
				if not line:
					continue
				try:
					record = json.loads(line)
				except ValueError:
					# A single malformed line must not abort a whole run; the
					# ingester counts these via the records_read/inserted gap.
					continue
				yield record
				emitted += 1
				if emitted >= limit:
					terminated_early = True
					break
		finally:
			if terminated_early:
				proc.terminate()
			if proc.stdout:
				proc.stdout.close()
			proc.wait()

			if not terminated_early and proc.returncode not in (0, None):
				errfile.seek(0)
				stderr = errfile.read().strip()
				if _CURSOR_LOST_MARKER in stderr:
					raise CursorLostError(stderr)
				raise JournalError(f"journalctl exited {proc.returncode}: {stderr[:500]}")


def read_batch(
	cursor: str | None = None, since_hours: int = 24, limit: int = 5000
) -> tuple[list[dict], str | None]:
	"""Materialise one batch of records and return it with the last cursor seen.

	The cursor returned is the one belonging to the last record ACTUALLY
	consumed, never the newest in the journal — so stopping early at `limit`
	leaves the remainder to be picked up by the next run rather than skipped.
	"""
	records: list[dict] = []
	last_cursor = cursor
	for record in read_records(cursor=cursor, since_hours=since_hours, limit=limit):
		records.append(record)
		if record.get("__CURSOR"):
			last_cursor = record["__CURSOR"]
	return records, last_cursor
