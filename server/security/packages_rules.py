# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What changed in the installed software, and what is overdue.

Two findings people actually act on, and a great deal of restraint about
everything else.

An unattended upgrade run touches eight hundred packages on this box in a
month. Reporting each one is not monitoring, it is a changelog nobody reads —
so ordinary upgrades are summarised into a single line and only INSTALLS and
REMOVALS are named, because those are the ones that change what the machine
can do rather than which version of it is running.

Pending updates get the same treatment. Twenty-five are waiting here and nine
are from the security pocket. A finding about twenty-five is wallpaper; a
finding about nine, with how long each has been sitting, is a decision.
"""

from __future__ import annotations

from server.security import packages
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "packages"


def _finding(severity: str, subject: str, detail: str, runbook: str) -> Finding:
	return Finding(severity, subject, detail, runbook, category=CATEGORY)


def judge_history(events: list[packages.PackageEvent]) -> list[Finding]:
	"""Software that arrived or left since the last look."""
	findings: list[Finding] = []
	if not events:
		return findings

	installs = [e for e in events if e.action == "install"]
	removals = [e for e in events if e.action in ("remove", "purge")]
	upgrades = [e for e in events if e.action == "upgrade"]

	notable = [e for e in installs if e.is_notable]
	if notable:
		findings.append(
			_finding(
				HIGH,
				f"Notable software was installed: {', '.join(sorted({e.package for e in notable}))}",
				f"Installed at {notable[0].when}. Each of these is a legitimate tool somebody may "
				f"need, and each is also a step taken early by someone who has just arrived — a "
				f"scanner, a tunnel, a compiler or a miner.",
				"Confirm you installed it, and on purpose, on this machine. If you did not, do not "
				"remove it yet: what was installed and when is one of the few reliable timestamps "
				"in an intrusion, and this app's SSH and sudo records for the same minute will "
				"usually name the session that did it.",
			)
		)

	ordinary = [e for e in installs if not e.is_notable]
	if ordinary:
		names = sorted({e.package for e in ordinary})
		findings.append(
			_finding(
				MEDIUM,
				f"{len(names)} package(s) were installed",
				f"{', '.join(names[:12])}{'…' if len(names) > 12 else ''}. Installed software "
				f"changes what this machine is able to do, which is a different question from "
				f"which version it is running.",
				"Match these against a deploy or a maintenance window you know about. A package "
				"install on a server nobody deployed to is one of the clearest signals there is.",
			)
		)

	if removals:
		names = sorted({e.package for e in removals})
		findings.append(
			_finding(
				MEDIUM,
				f"{len(names)} package(s) were removed",
				f"{', '.join(names[:12])}{'…' if len(names) > 12 else ''}.",
				"Usually housekeeping. Worth a look when the removed package is something that "
				"records what happens on the machine — auditd, rsyslog and this app's own "
				"dependencies included.",
			)
		)

	if upgrades:
		findings.append(
			_finding(
				INFO,
				f"{len({e.package for e in upgrades})} package(s) were upgraded",
				"Routine, and summarised rather than listed: an unattended-upgrades run touches "
				"hundreds at a time, and naming each one would bury the installs and removals "
				"above it.",
				"No action. The individual versions are in /var/log/dpkg.log if a specific one "
				"ever matters.",
			)
		)

	return findings


def judge_updates(snapshot: packages.Snapshot, now=None) -> list[Finding]:
	"""Security updates that have been waiting too long.

	Age, not count. There are always some pending — a finding that fires on
	their existence fires every day forever, and the reader learns to close it
	without reading. What is worth saying is that one has been pending for a
	fortnight.
	"""
	from datetime import datetime

	security = list(snapshot.security_updates)
	if not security:
		return []

	now = now or datetime.now()
	overdue = []
	for update in security:
		stamp = snapshot.first_seen.get(update.package)
		if not stamp:
			continue
		try:
			age = (now - datetime.fromisoformat(str(stamp))).days
		except (TypeError, ValueError):
			continue
		if age >= packages.SECURITY_UPDATE_GRACE_DAYS:
			overdue.append((update, age))

	if not overdue:
		return [
			_finding(
				INFO,
				f"{len(security)} security update(s) are pending",
				f"{', '.join(sorted(u.package for u in security)[:12])}. Within the "
				f"{packages.SECURITY_UPDATE_GRACE_DAYS}-day window, so this is a note rather than "
				f"a finding.",
				"Apply them at the next convenient point. This becomes a Medium once any of them "
				"has been waiting longer than that.",
			)
		]

	oldest = max(age for _, age in overdue)
	names = sorted(update.package for update, _ in overdue)
	return [
		_finding(
			MEDIUM if oldest < 30 else HIGH,
			f"{len(overdue)} security update(s) have been pending for over a week",
			f"{', '.join(names[:12])}{'…' if len(names) > 12 else ''}. The oldest has been waiting "
			f"{oldest} days. These are from the distribution's security pocket, so each one exists "
			f"because a vulnerability was published — which means the details are public and the "
			f"version installed here is named in them.",
			"`sudo apt update && sudo apt upgrade`, or fix unattended-upgrades if it is meant to be "
			"doing this. If a package is deliberately held back, hold it explicitly with "
			"`apt-mark hold` so the reason is recorded somewhere other than in somebody's memory.",
		)
	]


def judge_coverage(surfaces: list) -> list[Finding]:
	blind = [s for s in surfaces if not s.readable]
	if not blind:
		return []

	paths = ", ".join(sorted({f"{s.path} ({s.reason})" for s in blind}))
	return [
		_finding(
			MEDIUM,
			"Package state could not be read",
			f"Could not read: {paths}. Software arriving on this host, and security updates going "
			f"unapplied, are both unreported while that is true.",
			"/var/log/dpkg.log is world-readable on a stock Ubuntu and `apt list --upgradable` "
			"needs no privileges, so this usually means something non-standard rather than a "
			"permissions problem to grant around.",
		)
	]


def judge(snapshot: packages.Snapshot, now=None) -> list[Finding]:
	findings: list[Finding] = []
	findings.extend(judge_history(list(snapshot.events)))
	findings.extend(judge_updates(snapshot, now))
	findings.extend(judge_coverage(list(snapshot.surfaces)))
	return findings
