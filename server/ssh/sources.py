# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Deciding which log source to read from, and proving it actually works."""

from __future__ import annotations

import os
from functools import lru_cache

import frappe

from server.server.doctype.server_settings.server_settings import get_settings
from server.ssh import journal

SOURCE_JOURNALD = "journald"
SOURCE_AUTHLOG = "authlog"
SOURCE_NONE = "none"
SOURCE_DISABLED = "disabled"


@lru_cache(maxsize=1)
def _probe() -> tuple[str, str]:
	"""Probe the machine once per process. Returns (source, explanation).

	Cached because the probe shells out twice and the answer changes only when
	the machine's configuration changes — at which point `clear_cache()` (or a
	worker restart) is the right remedy.
	"""
	if journal.is_available():
		# "journalctl runs" is NOT sufficient. Without the adm/systemd-journal
		# group it runs happily and returns only this user's records, so every
		# sshd and sudo event is invisible. That failure mode presents as a
		# quiet server rather than an error, which is the worst possible way
		# for a security tool to break — so it is checked explicitly.
		if journal.can_read_system_records():
			return SOURCE_JOURNALD, "journald readable, system records visible"
		explanation = (
			"journalctl runs but returns no root-owned records — the bench user is "
			"probably not in the 'adm' or 'systemd-journal' group, so SSH events "
			"would be invisible rather than merely missing. Falling back to auth.log."
		)
	else:
		explanation = "journalctl not available"

	path = (get_settings().auth_log_path or "").strip()
	if path and os.access(path, os.R_OK):
		return SOURCE_AUTHLOG, f"{explanation}; {path} is readable"

	return SOURCE_NONE, f"{explanation}; {path or 'auth log path'} is not readable either"


def clear_cache() -> None:
	"""Drop the cached probe result. Call after changing groups or settings."""
	_probe.cache_clear()


def detect_source() -> tuple[str, str]:
	"""Return (source, explanation) honouring the operator's configuration.

	Rules, in order:
	1. Monitoring switched off entirely -> "disabled".
	2. An explicit pin -> that source, verbatim. A diagnosing admin is never
	   overruled, even if the probe disagrees.
	3. "Auto" -> whatever the probe found.
	"""
	settings = get_settings()
	configured = settings.get_log_source()

	if configured == SOURCE_DISABLED:
		return SOURCE_DISABLED, "SSH monitoring is switched off in Server Settings"
	if configured in (SOURCE_JOURNALD, SOURCE_AUTHLOG):
		return configured, f"pinned to {configured} in Server Settings"
	return _probe()


def record_detected_source(source: str) -> None:
	"""Publish the probe result on the settings form.

	`db_set` rather than `save`: this runs in a worker on every tick, and a
	full save would churn the settings document's change log for a value that
	is purely informational.
	"""
	frappe.db.set_value(
		"Server Settings", "Server Settings", "detected_log_source", source, update_modified=False
	)
