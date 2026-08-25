# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading authentication records out of the auth.log text file.

The fallback for machines without journald, or where the bench user cannot read
the system journal. It is strictly worse than the journal — no audit-session id,
no boot id, no opaque cursor — but it is universally available.

THE HARD PART IS ROTATION, not parsing. logrotate can either rename the file and
create a new one (the default, which changes the inode) or copy-and-truncate it
in place (which keeps the inode and resets the size). Tracking a byte offset
alone silently loses everything written between the last read and the rotation
in the first case, and re-reads the whole file in the second. Tracking
(inode, offset) together distinguishes them.

...and (inode, offset) is still not quite enough. A filesystem may hand the SAME
inode straight back when a file is deleted and recreated, and if the new file
has grown past the old offset by the time we look, both checks pass and we skip
everything in it. So the head of the file is fingerprinted too: appends never
change the first bytes, but a new incarnation of the file always does. This is
belt-and-braces on a narrow case, and it is worth it — the failure it prevents
is a silent hole in an audit log, which is precisely the thing this app exists
to stop happening.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator

#: Bytes of the file head used as a rotation fingerprint. Long enough to span at
#: least one full auth.log line, short enough to be a free read.
SIGNATURE_BYTES = 256


class AuthLogUnavailableError(Exception):
	"""The configured auth.log cannot be read."""


def _stat(path: str) -> os.stat_result:
	try:
		return os.stat(path)
	except OSError as exc:
		raise AuthLogUnavailableError(f"cannot stat {path}: {exc}") from exc


def file_signature(path: str, length: int | None = None) -> str | None:
	"""Fingerprint the head of a file as "<bytes>:<sha1>".

	The byte count is part of the value, not an implementation detail. A naive
	fixed-width hash cannot be compared while the file is still shorter than the
	window — it would change on every append and report rotation constantly. By
	recording how many bytes the hash covers, a later comparison can re-hash
	exactly that many bytes and get a meaningful answer at any file size.
	"""
	try:
		with open(path, "rb") as fh:
			head = fh.read(length if length is not None else SIGNATURE_BYTES)
	except OSError:
		return None
	if not head:
		return None
	return f"{len(head)}:{hashlib.sha1(head).hexdigest()}"


def signature_matches(path: str, signature: str | None) -> bool:
	"""Does `path` still begin with the bytes that `signature` was taken over?

	Appends never change a file's head, so a mismatch means this is a different
	file wearing the same inode. Returns True when there is nothing to compare —
	an absent fingerprint must not be read as evidence of rotation.
	"""
	if not signature or ":" not in signature:
		return True

	width, expected = signature.split(":", 1)
	try:
		width = int(width)
	except ValueError:
		return True

	current = file_signature(path, length=width)
	if current is None:
		return False

	current_width, current_hash = current.split(":", 1)
	if int(current_width) < width:
		# The file is now shorter than the window the fingerprint covered, so it
		# cannot be the same file grown longer.
		return False
	return current_hash == expected


def _read_from(path: str, offset: int, limit: int) -> tuple[list[str], int, int]:
	"""Read complete lines from `offset`. Returns (lines, new_offset, consumed).

	Only advances past a line that ended in a newline. rsyslog appends without
	locking, so the final line of the file can be half-written at the moment we
	read it; treating it as consumed would drop the rest of it forever.
	"""
	lines: list[str] = []
	with open(path, encoding="utf-8", errors="replace") as fh:
		fh.seek(offset)
		position = offset
		while len(lines) < limit:
			line = fh.readline()
			if not line:
				break
			if not line.endswith("\n"):
				# Partial trailing line — leave the offset before it.
				break
			position = fh.tell()
			lines.append(line.rstrip("\n"))
	return lines, position, len(lines)


def read_lines(
	path: str,
	inode: str | None = None,
	offset: int = 0,
	limit: int = 5000,
	signature: str | None = None,
) -> tuple[list[str], str, int, str | None]:
	"""Read up to `limit` new lines.

	Returns (lines, new_inode, new_offset, new_signature) — feed all four back
	on the next call.

	Rules, in order:
	1. No stored inode -> first run. Start at `offset` (normally 0).
	2. Stored inode differs -> the file was ROTATED AWAY by rename. What we were
	   reading is now `<path>.1`, so drain its tail before starting the new file.
	3. Same inode but a different head fingerprint -> the inode was REUSED for a
	   new file. Same treatment as (2).
	4. Same inode and fingerprint but the file is SHORTER than our offset ->
	   copytruncate. Start again at 0, with no tail to drain.
	5. Otherwise -> continue from `offset`.
	"""
	st = _stat(path)
	current_inode = str(st.st_ino)
	current_signature = file_signature(path)
	lines: list[str] = []

	inode_changed = bool(inode) and inode != current_inode
	head_changed = bool(signature) and not signature_matches(path, signature)

	if inode_changed or head_changed:
		rotated = f"{path}.1"
		if os.path.exists(rotated):
			# Only drain .1 if it really is the file we were reading; otherwise
			# we would replay an older rotation we already consumed.
			try:
				is_ours = str(_stat(rotated).st_ino) == inode or signature_matches(rotated, signature)
			except AuthLogUnavailableError:
				is_ours = False
			if is_ours:
				tail, rotated_offset, _ = _read_from(rotated, offset, limit)
				lines.extend(tail)

				# If the rotated file still has more than this run's budget,
				# STAY ON IT. The new offset used to be discarded and the
				# checkpoint moved to the fresh file at 0, so everything past
				# the first `limit` lines of the rotated file was abandoned
				# permanently — and a rotation is exactly when a busy log has
				# the most in it.
				#
				# Reporting the rotated file's own inode and offset makes the
				# next run take this same branch and resume where this one
				# stopped, because `is_ours` matches on that inode.
				if len(lines) >= limit:
					try:
						return lines, str(_stat(rotated).st_ino), rotated_offset, file_signature(rotated)
					except AuthLogUnavailableError:
						pass
		offset = 0
	elif inode and st.st_size < offset:
		offset = 0

	remaining = max(limit - len(lines), 0)
	if remaining:
		fresh, offset, _ = _read_from(path, offset, remaining)
		lines.extend(fresh)

	return lines, current_inode, offset, current_signature


def iter_lines(path: str, inode: str | None = None, offset: int = 0, limit: int = 5000) -> Iterator[str]:
	"""Convenience iterator for callers that do not need the new position."""
	yield from read_lines(path, inode=inode, offset=offset, limit=limit)[0]
