# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Deciding which changes matter, and how much.

Every rule here is written against an artefact from the intrusion that
motivated this module, rather than against a general idea of suspicious. That
is deliberate: a detector tuned on imagination produces alerts nobody can act
on, and the fastest way to kill an alerting system is to make its first week
noisy.

THE RULES FIRE ON CHANGE, NOT ON STATE. "A systemd unit not owned by a package"
is not a finding — this host has six of them and they are all legitimate, and
so does every host with SysV compatibility units. "A systemd unit that was not
here yesterday and is owned by no package" is a finding, and on a stable server
it is close to a positive indicator on its own.

Frappe-free: judgement is the part worth testing, and it tests with no site.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from server.security import persistence

CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
INFO = "Info"

CATEGORY = "persistence"

APPEARED = "Appeared"
MODIFIED = "Modified"
DISAPPEARED = "Disappeared"

#: Directories a legitimate service is rarely started from, and where every
#: payload in the incident lived.
SUSPICIOUS_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/opt/", "/usr/local/bin/", "/usr/local/sbin/", "/home/")

#: A path component beginning with a dot, anywhere. `/usr/.local` is the exact
#: shape — a hidden directory whose name is one character from a real one.
_HIDDEN_COMPONENT = re.compile(r"/\.[^/]")

#: Fetch-and-run, the signature of a cron entry that keeps a payload fresh. The
#: incident's root cron re-downloaded its miner every six hours.
_DOWNLOAD_AND_RUN = re.compile(
	r"\b(curl|wget|fetch)\b|base64\s+-d|\bnc\b\s|/dev/tcp/|\bchmod\s+\+?x\b|\|\s*(ba)?sh\b",
	re.IGNORECASE,
)

#: Software whose presence on an ERPNext host is the finding. Proxy panels and
#: miners are what generated the abuse reports that got the address blocked.
KNOWN_BAD = (
	"xmrig", "microsocks", "x-ui", "xray", "v2ray", "shadowsocks", "frpc", "frps",
	"dbs_ppy", "sifre_yonetici", "kdevtmpfsi", "kinsing",
)

#: Names that impersonate a service account or a system daemon.
IMPERSONATION = ("mysqld", "postgres", "redis", "systemd", "dbus", "kernel", "update")


@dataclass(frozen=True)
class Finding:
	severity: str
	subject: str
	detail: str
	runbook: str
	category: str = CATEGORY

	def as_dict(self) -> dict:
		return self.__dict__.copy()


def _exec_paths(item: persistence.Item) -> list[str]:
	"""The binaries a unit runs, without their arguments."""
	raw = (item.detail or {}).get("ExecStart") or ""
	paths = []
	for line in raw.splitlines():
		# systemd allows a leading -, @, +, ! prefix on the command.
		command = line.strip().lstrip("-@+!").strip()
		if command:
			paths.append(command.split()[0])
	return paths


def _is_suspicious_path(path: str) -> bool:
	return path.startswith(SUSPICIOUS_PREFIXES) or bool(_HIDDEN_COMPONENT.search(path))


def _mentions_known_bad(text: str) -> str:
	lowered = (text or "").lower()
	return next((name for name in KNOWN_BAD if name in lowered), "")


def _looks_non_english(text: str) -> bool:
	"""A description that is not plain ASCII English.

	`Sifre Yonetim Sistemi Servisi` — Turkish for "password management system
	service" — is the template. On an estate whose units are all Debian's or the
	bench's own, a description in another language is not a false positive
	waiting to happen.
	"""
	if not text:
		return False
	if any(ord(char) > 127 for char in text):
		return True
	# Turkish-specific words that appeared verbatim in the incident.
	return bool(re.search(r"\b(sifre|yonet\w*|sistem\w*|servis\w*)\b", text, re.IGNORECASE))


# ----------------------------------------------------------------------
# Change rules
# ----------------------------------------------------------------------


def judge(change_type: str, item: persistence.Item, previous_hash: str = "") -> list[Finding]:
	"""What, if anything, is worth saying about one change."""
	if change_type == APPEARED:
		return _judge_appeared(item)
	if change_type == MODIFIED:
		return _judge_modified(item, previous_hash)
	return _judge_disappeared(item)


def _judge_appeared(item: persistence.Item) -> list[Finding]:
	findings: list[Finding] = []
	kind, name = item.kind, item.identifier

	if kind == persistence.KIND_TIMER:
		findings.append(
			Finding(
				CRITICAL,
				f"New systemd timer: {name}",
				f"A timer that was not present at the last scan. Path {item.path or 'unknown'}, "
				f"owning package {item.package or 'NONE'}.",
				"A timer is separate from its service and survives that service being disabled — "
				"in the incident a timer silently resurrected a unit that had been stopped. "
				"Check `systemctl cat "
				f"{name}` and what it activates. A timer arriving with a package update is "
				"benign; one owned by no package on a server nobody deployed to is not.",
			)
		)
	elif kind == persistence.KIND_UNIT:
		severity = CRITICAL if not item.package_owned else MEDIUM
		findings.append(
			Finding(
				severity,
				f"New systemd unit: {name}",
				f"Path {item.path or 'unknown'}, owning package {item.package or 'NONE'}. "
				f"Runs: {(item.detail or {}).get('ExecStart') or 'unknown'}",
				"Compare against what you deployed. A unit owned by a dpkg package appeared with "
				"a package install and is almost always benign; one owned by nothing was put "
				"there by a person or a script. `systemctl cat "
				f"{name}` shows it in full.",
			)
		)
		findings.extend(_judge_unit_shape(item))
	elif kind == persistence.KIND_CRON:
		findings.append(
			Finding(
				CRITICAL,
				f"New scheduled command: {name}",
				f"Commands: {'; '.join((item.detail or {}).get('lines') or []) or 'none parsed'}",
				"Cron is where the incident kept its miner alive — restarted every three minutes "
				"and re-downloaded every six hours. Read the entry. If you did not add it, treat "
				"the host as compromised rather than removing the entry and moving on.",
			)
		)
		findings.extend(_judge_cron_content(item))
	elif kind == persistence.KIND_SUDOERS:
		findings.append(
			Finding(
				CRITICAL,
				f"New sudoers rule: {name}",
				f"A file appeared in the sudoers directory: {item.path}",
				"A new sudoers file grants privilege without touching group membership, which "
				"makes it quieter than adding someone to `sudo`. Read it with `visudo -c -f "
				f"{item.path}` and confirm you added it.",
			)
		)
	elif kind == persistence.KIND_PAM:
		findings.append(
			Finding(
				HIGH,
				f"New PAM configuration: {name}",
				f"A file appeared in the PAM directory: {item.path}",
				"PAM decides what happens on every authentication, and `pam_exec` in the wrong "
				"place is a backdoor that runs as root on each login. Compare against a known "
				"good host.",
			)
		)
	elif kind == persistence.KIND_MODULE:
		findings.append(
			Finding(
				HIGH,
				f"New kernel module loaded: {name}",
				"A module that was not loaded at the last scan.",
				"Most appear after a package update or new hardware. One that appears on a "
				"server whose hardware has not changed, and which you cannot attribute to an "
				"update, deserves `modinfo "
				f"{name}`.",
			)
		)
	elif kind == persistence.KIND_SHELL_INIT:
		findings.append(
			Finding(
				HIGH,
				f"New shell init file: {name}",
				f"Path {item.path}",
				"Anything here runs on every interactive login. Read it.",
			)
		)
	elif kind == persistence.KIND_BOOT:
		findings.append(
			Finding(
				CRITICAL,
				f"Boot script appeared: {name}",
				f"Path {item.path}",
				"`/etc/rc.local` is absent on a modern Debian host. Its appearance means someone "
				"wanted something to run at boot without leaving a systemd unit to find.",
			)
		)

	findings.extend(_judge_names(item))
	return findings


def _judge_unit_shape(item: persistence.Item) -> list[Finding]:
	"""The shape of the units in the incident, independent of their names."""
	findings = []
	detail = item.detail or {}
	restart = (detail.get("Restart") or "").strip().lower()
	user = (detail.get("User") or "root").strip()
	description = detail.get("Description") or ""

	for path in _exec_paths(item):
		if _is_suspicious_path(path):
			findings.append(
				Finding(
					CRITICAL,
					f"Unit {item.identifier} runs from {path}",
					f"ExecStart points at {path}, as user {user}, Restart={restart or 'no'}.",
					"Every payload in the incident was started from /usr/local/bin, /opt or a "
					"hidden directory, by a unit that restarted it forever. A packaged service "
					"runs from /usr/bin or /usr/sbin. Check what that binary is before stopping "
					"anything — the file is evidence.",
				)
			)
			break

	if restart == "always" and user in ("root", "") and not item.package_owned:
		findings.append(
			Finding(
				CRITICAL,
				f"Unit {item.identifier} restarts forever as root",
				f"Restart=always, User={user or 'root'}, owned by no package. "
				f"Runs: {detail.get('ExecStart') or 'unknown'}",
				"This is the exact shape of the persistence in the incident: an unpackaged unit "
				"that runs as root and comes back whenever it is killed. Legitimate services "
				"with this shape are almost always package-owned.",
			)
		)

	if description and not item.package_owned and _looks_non_english(description):
		findings.append(
			Finding(
				HIGH,
				f"Unit {item.identifier} has an unexpected description",
				f'Description="{description}", owned by no package.',
				"The incident's credential stealer described itself in Turkish, and others "
				"impersonated 'Update Service' and 'D-Bus Connection Bus'. A unit describing "
				"itself in a language nothing else on this host uses is worth reading in full.",
			)
		)
	return findings


def _judge_cron_content(item: persistence.Item) -> list[Finding]:
	findings = []
	for line in (item.detail or {}).get("lines") or []:
		if _DOWNLOAD_AND_RUN.search(line):
			findings.append(
				Finding(
					CRITICAL,
					f"Scheduled command downloads and runs code: {item.identifier}",
					f"Entry: {line[:400]}",
					"A schedule that fetches and executes is how a payload survives being "
					"deleted — the incident re-downloaded its miner every six hours. Read the "
					"URL it fetches from before removing anything.",
				)
			)
			break
	return findings


def _judge_names(item: persistence.Item) -> list[Finding]:
	"""Names that are the finding on their own."""
	haystack = " ".join(
		[item.identifier, item.path or "", str((item.detail or {}).get("ExecStart") or "")]
	)
	match = _mentions_known_bad(haystack)
	if match:
		return [
			Finding(
				CRITICAL,
				f"Known proxy or miner software referenced: {match}",
				f"{item.kind} {item.identifier} references '{match}'. Path {item.path or 'unknown'}.",
				"This is proxy, tunnelling or mining software. On an ERPNext host none of it has "
				"a legitimate reason to exist, and it is what generates the outbound abuse that "
				"gets an address blocked. Preserve the binary before removing it.",
			)
		]
	return []


def _judge_modified(item: persistence.Item, previous_hash: str) -> list[Finding]:
	kind, name = item.kind, item.identifier

	if kind == persistence.KIND_PRELOAD:
		return [
			Finding(
				CRITICAL,
				"/etc/ld.so.preload changed",
				f"Entries: {(item.detail or {}).get('entries') or 'none'}",
				"This file is absent or empty on every clean host. A library listed here is "
				"loaded into every process that starts, which is the classic way to hide "
				"processes and files from the tools you would use to look for them. Treat "
				"anything this reports about the host afterwards as unreliable.",
			)
		]

	severity = {
		persistence.KIND_CRON: CRITICAL,
		persistence.KIND_SUDOERS: CRITICAL,
		persistence.KIND_PAM: CRITICAL,
		persistence.KIND_SHELL_INIT: HIGH,
		persistence.KIND_BOOT: CRITICAL,
	}.get(kind, HIGH)

	findings = [
		Finding(
			severity,
			f"{kind} changed: {name}",
			f"Content hash {previous_hash[:12] or 'unknown'} -> {item.content_hash[:12]}. "
			f"Path {item.path or 'unknown'}, owning package {item.package or 'NONE'}.",
			"Compare against what you changed. A file that belongs to a package and changed "
			"without a package upgrade is the strongest single signal here — `dpkg -V` will "
			"confirm it independently.",
		)
	]
	if kind == persistence.KIND_CRON:
		findings.extend(_judge_cron_content(item))
	if kind in (persistence.KIND_UNIT, persistence.KIND_TIMER):
		findings.extend(_judge_unit_shape(item))
	findings.extend(_judge_names(item))
	return findings


def _judge_disappeared(item: persistence.Item) -> list[Finding]:
	"""Something going away is usually maintenance, occasionally cleanup.

	Reported at a lower tier deliberately: a removal that surprises you is worth
	knowing about, but treating every uninstall as an incident is how the noise
	starts.
	"""
	if item.kind in (persistence.KIND_PAM, persistence.KIND_SUDOERS):
		return [
			Finding(
				HIGH,
				f"{item.kind} removed: {item.identifier}",
				f"Path {item.path or 'unknown'}",
				"Removing a PAM or sudoers file changes who can authenticate or escalate. If you "
				"did not remove it, find out what did.",
			)
		]
	return [
		Finding(
			INFO,
			f"{item.kind} removed: {item.identifier}",
			f"Path {item.path or 'unknown'}",
			"Usually a package removal. Worth a glance if you were not expecting it.",
		)
	]


# ----------------------------------------------------------------------
# Coverage
# ----------------------------------------------------------------------


def judge_coverage(surfaces: list[persistence.Surface]) -> list[Finding]:
	"""A surface that could not be read is a finding, not a gap to shrug at.

	Running as the bench user, the per-user cron spool and /etc/sudoers are
	unreadable — and the spool is exactly where a root cron entry re-downloading
	a payload would live. A scan that reports "no cron entries" for a directory
	it could not open is worse than one that collects nothing, because the empty
	answer reads as clean.
	"""
	blind = [s for s in surfaces if not s.readable and s.reason != "does not exist"]
	if not blind:
		return []

	paths = ", ".join(sorted({s.path for s in blind if s.path}))
	return [
		Finding(
			HIGH,
			"Some persistence surfaces could not be read",
			f"Unreadable: {paths}",
			"These are not being monitored, and the scan cannot tell the difference between "
			"'nothing there' and 'could not look'. The per-user cron spool matters most: it is "
			"where a root schedule would live. Either give this app a NOPASSWD sudoers rule for "
			"a read-only helper, or accept the reduced coverage knowingly — but do not leave it "
			"looking like the surfaces are clean.",
		)
	]
