# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Single DocType holding every operator-tunable knob in this app.

House pattern: the settings document is not a passive bag of fields, it is where
the rules that interpret those fields live. Callers ask it questions
(`get_ignored_programs()`, `assert_installs_allowed()`) rather than reading raw
values and re-deriving the same logic in three places.
"""

import os

import frappe
from frappe.model.document import Document

#: Programs whose events this app exists to record. Blocking one of these via
#: `ignore_programs` would silently disable the feature, so it is refused.
PROTECTED_PROGRAMS = {"sshd", "sshd-session", "sudo"}

#: ip-api.com rejects a batch larger than this outright.
MAX_GEO_BATCH = 100


class ServerSettings(Document):
	# ------------------------------------------------------------------
	# Validation
	# ------------------------------------------------------------------

	def validate(self):
		self._validate_ignore_programs()
		self._validate_numeric_bounds()
		self._validate_paths()

	def _validate_ignore_programs(self):
		blocked = PROTECTED_PROGRAMS & self.get_ignored_programs()
		if blocked:
			frappe.throw(
				f"Ignore Programs cannot contain {', '.join(sorted(blocked))} — "
				"those are the programs this app exists to monitor. Ignoring them "
				"would stop SSH tracking without any other sign that it had stopped.",
				title="Would Disable Monitoring",
			)

	def _validate_numeric_bounds(self):
		if self.max_records_per_run is not None and self.max_records_per_run < 1:
			frappe.throw("Max Records Per Run must be at least 1.")
		if self.bootstrap_hours is not None and self.bootstrap_hours < 1:
			frappe.throw("Bootstrap Hours must be at least 1.")
		if self.geo_batch_size and self.geo_batch_size > MAX_GEO_BATCH:
			frappe.throw(f"Batch Size cannot exceed {MAX_GEO_BATCH} — the provider rejects larger batches.")
		if self.failed_login_threshold is not None and self.failed_login_threshold < 1:
			frappe.throw("Failed Login Threshold must be at least 1.")
		if self.install_timeout_seconds is not None and self.install_timeout_seconds < 30:
			frappe.throw("Install Timeout must be at least 30 seconds — a git clone cannot finish faster.")

	def _validate_paths(self):
		# A relative bench executable is the classic "works in my shell, hangs in
		# the worker" bug: RQ workers do not inherit an interactive PATH.
		if self.bench_executable and not self.bench_executable.startswith("/"):
			frappe.throw(
				"Bench Executable must be an absolute path. Background workers do not "
				"inherit your login shell's PATH, so a bare 'bench' will not resolve.",
			)
		if self.bench_root and not self.bench_root.startswith("/"):
			frappe.throw("Bench Root must be an absolute path.")

	# ------------------------------------------------------------------
	# SSH monitoring
	# ------------------------------------------------------------------

	def get_log_source(self) -> str:
		"""Return the configured log source, normalised for the ingester.

		Rules, in order:
		1. Monitoring disabled entirely -> "disabled".
		2. An explicit pin -> that source, honoured verbatim so a diagnosing
		   admin is never second-guessed.
		3. "Auto" -> "auto", meaning the ingester probes for itself.
		"""
		if not self.ssh_monitoring_enabled:
			return "disabled"
		return {
			"Journald": "journald",
			"Auth Log": "authlog",
			"Disabled": "disabled",
		}.get(self.log_source or "Auto", "auto")

	def get_ignored_programs(self) -> set[str]:
		"""Syslog program names to drop before parsing."""
		raw = self.ignore_programs or ""
		return {line.strip() for line in raw.splitlines() if line.strip()}

	# ------------------------------------------------------------------
	# Geolocation
	# ------------------------------------------------------------------

	def get_geo_resolver_name(self) -> str:
		"""Return the active resolver key, or "" when geolocation is off."""
		if not self.geo_enabled:
			return ""
		resolver = (self.geo_resolver or "").strip()
		return "" if resolver in ("", "Disabled") else resolver

	def get_geo_batch_size(self) -> int:
		return min(int(self.geo_batch_size or MAX_GEO_BATCH), MAX_GEO_BATCH)

	def get_geo_api_key(self) -> str | None:
		return self.get_password("geo_api_key", raise_exception=False)

	# ------------------------------------------------------------------
	# Alerting
	# ------------------------------------------------------------------

	def get_alert_recipients(self) -> list[str]:
		"""Who to notify.

		Rules, in order:
		1. Alerting disabled -> nobody.
		2. An explicit list -> exactly those addresses.
		3. Empty list -> every enabled System Manager. An unconfigured field
		   must never resolve to "tell nobody"; that is how a breach goes
		   unnoticed twice.
		"""
		if not self.alerts_enabled:
			return []

		configured = [line.strip() for line in (self.alert_recipients or "").splitlines() if line.strip()]
		if configured:
			return configured

		managers = frappe.get_all(
			"Has Role",
			filters={"role": "System Manager", "parenttype": "User"},
			pluck="parent",
		)
		if not managers:
			return []
		return frappe.get_all(
			"User",
			filters={"name": ("in", managers), "enabled": 1, "user_type": "System User"},
			pluck="name",
		)

	def get_trusted_countries(self) -> set[str]:
		"""Uppercase ISO-2 codes exempt from the new-country alert."""
		raw = self.trusted_countries or ""
		return {line.strip().upper() for line in raw.splitlines() if line.strip()}

	# ------------------------------------------------------------------
	# Bench management
	# ------------------------------------------------------------------

	def get_bench_root(self) -> str:
		"""Directory to scan for benches, defaulting to this bench's parent."""
		if self.bench_root:
			return self.bench_root.rstrip("/")
		return os.path.dirname(frappe.utils.get_bench_path().rstrip("/"))

	def get_bench_env(self) -> dict[str, str]:
		"""Environment for every subprocess that may touch git.

		The three variables below are what stop a background job hanging forever
		on a prompt no one can answer:
		- GIT_TERMINAL_PROMPT=0 makes git fail rather than ask for credentials.
		- GIT_SSH_COMMAND carries BatchMode=yes, so ssh fails rather than ask for
		  a key passphrase. There is no ssh-agent running under the worker.
		- GIT_ASKPASS is emptied so git cannot fall back to a graphical prompt.
		"""
		env = os.environ.copy()
		env["GIT_TERMINAL_PROMPT"] = "0"
		env["GIT_ASKPASS"] = ""
		env["SSH_ASKPASS"] = ""
		if self.git_ssh_command:
			env["GIT_SSH_COMMAND"] = self.git_ssh_command
		return env

	def assert_installs_allowed(self) -> None:
		"""Raise unless the operator has armed the install interlock.

		Deliberately re-checked inside the background job as well as in the API
		layer: the interlock can be switched off between a request being queued
		and the worker picking it up, and the later check is the one that counts.
		"""
		if not self.allow_app_install:
			frappe.throw(
				"App installs are disabled. Turn on Allow App Installs in "
				"Server Settings before running an App Install Request.",
				frappe.PermissionError,
				title="Installs Disabled",
			)

	def get_install_timeout(self) -> int:
		return int(self.install_timeout_seconds or 1800)


def get_settings() -> "ServerSettings":
	"""Fetch the settings document.

	Uses the cached read: this is consulted on every ingest tick and every geo
	batch, and the values change at human speed, not machine speed.
	"""
	return frappe.get_cached_doc("Server Settings")
