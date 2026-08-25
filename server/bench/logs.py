# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading a bench's log files.

When a bench misbehaves the answer is almost always in `logs/`, and getting to
it means an SSH session, remembering which of fifteen files is the right one,
and knowing that the interesting part is at the end. This puts the same files
one click away with the tail already showing.

Read-only, and only ever from inside the bench's own log directories — the
paths come from a browser, and a log reader that will open any file on the
server is a file-disclosure hole rather than a feature.

Frappe-free, so it tests against a temp directory with no site.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

#: Read from the END of the file. A worker.log is routinely hundreds of
#: megabytes and the last few hundred lines are the entire point; loading the
#: whole thing to take the tail would be both slow and a way to exhaust memory.
TAIL_CHUNK = 64 * 1024

#: Hard cap on a single read, whatever the caller asks for.
MAX_LINES = 5000
DEFAULT_LINES = 300

#: Files worth offering. `.log.1` and friends are rotations and are included —
#: the thing you are looking for is often just past midnight.
LOG_PATTERN = re.compile(r"\.log(\.\d+)?$|\.log\.gz$")

#: A one-line explanation for the files a bench always has, so the picker is
#: readable by someone who has not memorised what writes to what.
KNOWN = {
	"bench.log": "bench's own CLI actions — every get-app, migrate and build run from the terminal.",
	"worker.log": "Background jobs. Where a queued task says what it did.",
	"worker.error.log": "Background jobs that raised. Usually the first place to look.",
	"web.log": "Gunicorn access and startup.",
	"web.error.log": "Unhandled exceptions from web requests.",
	"scheduler.log": "The scheduler tick — proves whether scheduled jobs are firing at all.",
	"schedule.log": "The scheduler process itself.",
	"database.log": "Slow and failing queries.",
	"frappe.log": "The framework's own logger.",
	"backup.log": "Scheduled backups.",
	"redis-cache.log": "Redis cache instance.",
	"redis-queue.log": "Redis queue instance.",
	"server.log": "This app's logger.",
	"ipython.log": "bench console sessions.",
}


@dataclass(frozen=True)
class LogFile:
	name: str
	path: str
	scope: str
	size: int
	size_text: str
	modified: float
	modified_text: str
	description: str
	is_rotation: bool


def _human(count: float) -> str:
	value = float(count)
	for unit in ("B", "KB", "MB", "GB"):
		if value < 1024 or unit == "GB":
			return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
		value /= 1024
	return f"{value:.1f} GB"


def log_directories(bench_path: str, sites: list[str] | None = None) -> list[tuple[str, str]]:
	"""Every directory a bench keeps logs in, with a label for each."""
	found = [(os.path.join(bench_path, "logs"), "bench")]
	for site in sites or []:
		found.append((os.path.join(bench_path, "sites", site, "logs"), site))
	return found


def is_inside(roots: list[str], path: str) -> bool:
	"""True when `path` resolves to somewhere under one of `roots`.

	Resolved, not compared as strings: `../../etc/passwd` and a symlink planted
	in the log directory both defeat a prefix check.
	"""
	try:
		real = os.path.realpath(path)
	except OSError:
		return False
	for root in roots:
		try:
			root_real = os.path.realpath(root)
		except OSError:
			continue
		if os.path.commonpath([root_real, real]) == root_real:
			return True
	return False


def list_logs(bench_path: str, sites: list[str] | None = None) -> list[LogFile]:
	"""Every log file in the bench, biggest-recent first.

	Sorted by modification time rather than name: the file that changed a minute
	ago is nearly always the one being asked about.
	"""
	found: list[LogFile] = []
	for directory, scope in log_directories(bench_path, sites):
		if not os.path.isdir(directory):
			continue
		try:
			entries = list(os.scandir(directory))
		except OSError:
			continue

		for entry in entries:
			if not entry.is_file() or not LOG_PATTERN.search(entry.name):
				continue
			try:
				stat = entry.stat()
			except OSError:
				continue
			base = re.sub(r"\.\d+$", "", entry.name)
			found.append(
				LogFile(
					name=entry.name,
					path=entry.path,
					scope=scope,
					size=stat.st_size,
					size_text=_human(stat.st_size),
					modified=stat.st_mtime,
					modified_text=_when(stat.st_mtime),
					description=KNOWN.get(base, ""),
					is_rotation=base != entry.name,
				)
			)

	found.sort(key=lambda f: f.modified, reverse=True)
	return found


def _when(timestamp: float) -> str:
	import time

	delta = time.time() - timestamp
	if delta < 90:
		return "just now"
	if delta < 3600:
		return f"{int(delta // 60)} min ago"
	if delta < 86400:
		return f"{int(delta // 3600)}h ago"
	return f"{int(delta // 86400)}d ago"


def tail(path: str, lines: int = DEFAULT_LINES, search: str | None = None) -> dict:
	"""The last `lines` lines of a file, optionally filtered.

	Seeks backwards in chunks rather than reading forwards. A worker.log of
	600 MB is routine on a busy bench, and reading it to reach the end would
	take seconds and hold all of it in memory to throw nearly all of it away.

	When searching, the whole file has to be scanned — but it is streamed line
	by line and only matches are kept, so memory stays bounded by the result
	rather than by the file.
	"""
	lines = max(1, min(lines, MAX_LINES))
	try:
		size = os.path.getsize(path)
	except OSError as exc:
		return {"error": str(exc), "lines": [], "size": 0, "truncated": False}

	if search:
		return _search(path, search, lines, size)

	collected: list[str] = []
	try:
		with open(path, "rb") as handle:
			position = size
			block = b""
			while position > 0 and block.count(b"\n") <= lines:
				step = min(TAIL_CHUNK, position)
				position -= step
				handle.seek(position)
				block = handle.read(step) + block
			collected = block.decode("utf-8", errors="replace").splitlines()
	except OSError as exc:
		return {"error": str(exc), "lines": [], "size": size, "truncated": False}

	truncated = len(collected) > lines
	return {
		"error": None,
		"lines": collected[-lines:],
		"size": size,
		"size_text": _human(size),
		"truncated": truncated,
		"matched": None,
	}


def _search(path: str, term: str, limit: int, size: int) -> dict:
	"""Lines containing `term`, the last `limit` of them.

	Case-insensitive, because nobody remembers whether the log said "Error" or
	"ERROR", and getting nothing back reads as "it never happened".
	"""
	needle = term.lower()
	matches: list[str] = []
	# Counted separately from the list. The list is a ring buffer trimmed back
	# to `limit`, so its length is the size of the retained tail and never the
	# number of matches — reporting it said "398 matching lines" for a file
	# where every one of 1000 lines matched, and claimed nothing was truncated
	# while silently dropping most of them.
	found = 0
	scanned = 0
	try:
		with open(path, encoding="utf-8", errors="replace") as handle:
			for line in handle:
				scanned += 1
				if needle in line.lower():
					found += 1
					matches.append(line.rstrip("\n"))
					# Keep only the tail, so a term that appears a million times
					# cannot exhaust memory.
					if len(matches) > limit * 2:
						del matches[: len(matches) - limit]
	except OSError as exc:
		return {"error": str(exc), "lines": [], "size": size, "truncated": False}

	return {
		"error": None,
		"lines": matches[-limit:],
		"size": size,
		"size_text": _human(size),
		"truncated": found > limit,
		"matched": found,
		"scanned": scanned,
	}
