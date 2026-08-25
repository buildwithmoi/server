# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading what a backup needs, before restoring it.

`bench restore` loads a database that references apps by name. If the bench
does not have one of them, the restore appears to succeed and the site is
broken — every DocType belonging to the missing app is gone, and the failure
surfaces later as import errors nobody connects to the restore.

Finding that out afterwards is the expensive way. A frappe dump carries the
answer in `tabInstalled Application`: the app name, the version, and the git
branch it was installed from. This reads it out of the dump without loading
anything, so the missing apps can be cloned first.

The dump is streamed and decompressed on the fly. A production dump is
routinely gigabytes and holding one in memory to grep it would be worse than
the problem being solved.

Frappe-free, so it tests against a fixture with no site.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
from dataclasses import dataclass, field

#: The table that answers the question.
APPS_TABLE = "tabInstalled Application"

#: Give up after this much. mysqldump writes tables roughly in name order, so
#: `tabInstalled Application` appears early — but a dump that does not contain
#: it at all must not cost a full read of 40 GB before saying so.
MAX_SCAN_BYTES = 4 * 1024 * 1024 * 1024

#: Decompressed chunk size for the streaming read.
CHUNK = 1024 * 1024

_CREATE = re.compile(rf"CREATE TABLE [`\"]?{re.escape(APPS_TABLE)}[`\"]?\s*\((?P<body>.*?)\)\s*ENGINE", re.S)
_COLUMN = re.compile(r"^\s*[`\"](?P<name>\w+)[`\"]\s+\w", re.M)
_INSERT = re.compile(rf"INSERT INTO [`\"]?{re.escape(APPS_TABLE)}[`\"]? VALUES\s*(?P<rows>.*?);", re.S)


class NotReadable(Exception):
	"""Raised when a dump cannot be inspected."""


@dataclass(frozen=True)
class BackupApp:
	"""One app the backup expects the bench to have."""

	app_name: str
	app_version: str = ""
	git_branch: str = ""
	#: Filled in by `compare`, against what the bench actually has.
	present: bool = False
	branch_matches: bool = True
	installed_branch: str = ""

	@property
	def note(self) -> str:
		if not self.present:
			return "Not on this bench — clone it before restoring."
		if not self.branch_matches:
			return (
				f"On this bench at {self.installed_branch}, but the backup was taken on "
				f"{self.git_branch}."
			)
		return "Ready."


@dataclass
class BackupContents:
	"""What a backup turned out to contain."""

	apps: list[BackupApp] = field(default_factory=list)
	site_config_keys: list[str] = field(default_factory=list)
	source: str = ""
	scanned_bytes: int = 0
	truncated: bool = False
	error: str = ""

	def as_dict(self) -> dict:
		return {
			"apps": [app.__dict__ | {"note": app.note} for app in self.apps],
			"site_config_keys": self.site_config_keys,
			"source": self.source,
			"scanned_bytes": self.scanned_bytes,
			"truncated": self.truncated,
			"error": self.error,
			"missing": [app.app_name for app in self.apps if not app.present],
		}


# ----------------------------------------------------------------------
# Reading the dump
# ----------------------------------------------------------------------


def _open(path: str):
	"""Open a dump for streaming, transparently decompressing gzip."""
	handle = open(path, "rb")
	try:
		if handle.read(2) == b"\x1f\x8b":
			handle.seek(0)
			return gzip.open(handle, "rb")
		handle.seek(0)
		return handle
	except Exception:
		handle.close()
		raise


def _split_row(row: str) -> list[str]:
	"""Split one SQL VALUES tuple into its columns.

	Hand-written rather than a regex because a value can contain a comma, a
	quote escaped as `\\'`, or a doubled `''` — and a naive split on commas
	silently shifts every column after the first address or description.
	"""
	values: list[str] = []
	current: list[str] = []
	in_string = False
	escaped = False

	for char in row:
		if escaped:
			current.append(char)
			escaped = False
		elif char == "\\" and in_string:
			escaped = True
		elif char == "'":
			in_string = not in_string
			current.append(char)
		elif char == "," and not in_string:
			values.append("".join(current).strip())
			current = []
		else:
			current.append(char)

	values.append("".join(current).strip())
	return [_unquote(value) for value in values]


def _unquote(value: str) -> str:
	value = value.strip()
	if value.upper() == "NULL":
		return ""
	if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
		return value[1:-1].replace("\\'", "'").replace("''", "'").replace("\\\\", "\\")
	return value


def read_apps(database_path: str) -> BackupContents:
	"""The apps a dump expects, read without loading it.

	Column positions are taken from the dump's own CREATE TABLE rather than
	hardcoded. frappe has added columns to this table before, and a fixed index
	would quietly start reporting the version as the branch.
	"""
	contents = BackupContents(source=os.path.basename(database_path))

	try:
		stream = _open(database_path)
	except OSError as exc:
		contents.error = f"Could not open the dump: {exc}"
		return contents

	buffer = io.StringIO()
	columns: list[str] = []
	try:
		with stream:
			while contents.scanned_bytes < MAX_SCAN_BYTES:
				chunk = stream.read(CHUNK)
				if not chunk:
					break
				contents.scanned_bytes += len(chunk)
				buffer.write(chunk.decode("utf-8", errors="replace"))
				text = buffer.getvalue()

				if not columns:
					create = _CREATE.search(text)
					if create:
						columns = _COLUMN.findall(create.group("body"))

				if columns:
					insert = _INSERT.search(text)
					if insert:
						contents.apps = _parse_rows(insert.group("rows"), columns)
						return contents

				# Keep only enough tail to span a statement that straddles a
				# chunk boundary. Without this the buffer becomes the whole dump.
				if len(text) > 4 * CHUNK:
					buffer = io.StringIO()
					buffer.write(text[-2 * CHUNK :])
			else:
				contents.truncated = True
	except (OSError, EOFError, gzip.BadGzipFile) as exc:
		contents.error = (
			f"Could not read the dump: {exc}. If it is encrypted, its apps cannot be listed "
			"without the key."
		)
		return contents

	if not contents.apps and not contents.error:
		contents.error = (
			"No installed-application table found in this dump. It may be a partial backup, or "
			"from a version of frappe that records this differently."
		)
	return contents


def _parse_rows(rows: str, columns: list[str]) -> list[BackupApp]:
	index = {name: position for position, name in enumerate(columns)}
	name_at = index.get("app_name")
	if name_at is None:
		return []

	found: dict[str, BackupApp] = {}
	for match in re.finditer(r"\((?P<row>(?:[^()']|'(?:\\.|''|[^'])*')*)\)", rows, re.S):
		values = _split_row(match.group("row"))
		if len(values) <= name_at:
			continue
		app_name = values[name_at]
		if not app_name:
			continue
		found[app_name] = BackupApp(
			app_name=app_name,
			app_version=_at(values, index.get("app_version")),
			git_branch=_at(values, index.get("git_branch")),
		)

	return sorted(found.values(), key=lambda app: app.app_name)


def _at(values: list[str], position: int | None) -> str:
	if position is None or position >= len(values):
		return ""
	return values[position]


def read_site_config(path: str | None) -> list[str]:
	"""Keys present in the backup's site_config snapshot.

	Only the key NAMES. The snapshot contains the database password and the
	encryption key, and this is rendered in a browser.
	"""
	if not path or not os.path.isfile(path):
		return []
	try:
		with open(path) as handle:
			return sorted(json.load(handle).keys())
	except (OSError, ValueError):
		return []


# ----------------------------------------------------------------------
# Comparing against a bench
# ----------------------------------------------------------------------


def compare(contents: BackupContents, installed: dict[str, str]) -> BackupContents:
	"""Mark which apps the bench already has, and on which branch.

	`installed` maps app name to the branch it is checked out at.
	"""
	compared = []
	for app in contents.apps:
		branch = installed.get(app.app_name)
		present = branch is not None
		compared.append(
			BackupApp(
				app_name=app.app_name,
				app_version=app.app_version,
				git_branch=app.git_branch,
				present=present,
				installed_branch=branch or "",
				# Only a mismatch when both sides actually name a branch.
				branch_matches=not (present and app.git_branch and branch and branch != app.git_branch),
			)
		)
	contents.apps = compared
	return contents
