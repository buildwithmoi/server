# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What software is on this host, what changed, and what is waiting to be patched.

`filesystem.py` asks whether the files a package installed are still the files
it installed. This asks a different question: what packages arrived, what left,
and what the distribution is telling us to update.

THREE SIGNALS, ALL CHEAP AND ALL READABLE WITHOUT ROOT on a normal Ubuntu box:

  dpkg history.       `/var/log/dpkg.log` records every install, remove and
                      upgrade with a timestamp. A package appearing on a server
                      nobody deployed to is one of the clearest signals there
                      is -- an intruder who wants a compiler, a scanner or a
                      tunnel usually just installs one.
  Pending updates.    `apt list --upgradable` names them and, crucially, names
                      the POCKET. On this box 25 updates are pending and 9 are
                      from `noble-security`. Those nine are the ones that
                      matter; treating all 25 alike is how the number becomes
                      wallpaper.
  Update age.         A count of pending security updates says nothing on its
                      own -- there are always some. How LONG they have been
                      pending is the finding, so the first time each is seen is
                      recorded and the age is measured from there.

Frappe-free. `packages_rules.py` judges; the first-seen dates are stored by
`watch.py` in `Security Baseline`.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from server.security.persistence import Surface

KIND_HISTORY = "package-history"
KIND_UPDATES = "package-updates"

DPKG_LOG = "/var/log/dpkg.log"

#: Actions worth recording. `status`, `configure` and `trigproc` are dpkg
#: talking to itself -- 8,574 status lines here against 1,214 installs -- and
#: keeping them would bury the three verbs that mean something happened.
INTERESTING_ACTIONS = ("install", "remove", "purge", "upgrade")

#: Packages whose arrival on a server is worth saying out loud. Not a blocklist
#: -- every one of these is a legitimate tool somebody may need -- but each is
#: also a step an intruder takes early, and their appearance on a production
#: box that nobody deployed to is a question worth asking.
NOTABLE = frozenset(
	{
		"nmap", "masscan", "zmap", "hydra", "john", "hashcat", "sqlmap",
		"netcat", "netcat-openbsd", "netcat-traditional", "socat", "ncat",
		"tcpdump", "tshark", "ettercap-text-only",
		"proxychains", "proxychains4", "tor", "openvpn", "wireguard",
		"gcc", "g++", "make", "build-essential", "clang",
		"xmrig", "cpuminer", "minerd",
	}
)

#: How long a pending security update is tolerated before it is a finding.
SECURITY_UPDATE_GRACE_DAYS = 7

_DPKG_LINE = re.compile(
	r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
	r"(?P<action>\w+)\s+(?P<package>[^\s:]+)(?::\S+)?\s+(?P<old>\S+)(?:\s+(?P<new>\S+))?\s*$"
)

_UPGRADABLE_LINE = re.compile(
	r"^(?P<package>[^/\s]+)/(?P<pockets>\S+)\s+(?P<candidate>\S+)\s+(?P<arch>\S+)"
	r"\s+\[upgradable from:\s*(?P<installed>[^\]]+)\]"
)


@dataclass(frozen=True)
class PackageEvent:
	when: datetime
	action: str
	package: str
	old_version: str = ""
	new_version: str = ""

	@property
	def is_notable(self) -> bool:
		return self.package in NOTABLE

	def as_dict(self) -> dict:
		return {
			"when": str(self.when),
			"action": self.action,
			"package": self.package,
			"old_version": self.old_version,
			"new_version": self.new_version,
		}


@dataclass(frozen=True)
class Upgradable:
	package: str
	installed: str
	candidate: str
	pockets: tuple[str, ...] = ()

	@property
	def is_security(self) -> bool:
		return any("security" in pocket for pocket in self.pockets)

	def as_dict(self) -> dict:
		return {
			"package": self.package,
			"installed": self.installed,
			"candidate": self.candidate,
			"pockets": list(self.pockets),
			"security": self.is_security,
		}


@dataclass(frozen=True)
class Snapshot:
	events: tuple[PackageEvent, ...] = ()
	upgradable: tuple[Upgradable, ...] = ()
	surfaces: tuple[Surface, ...] = ()
	#: package -> ISO date it was first seen pending, supplied by the caller.
	first_seen: dict = field(default_factory=dict)

	@property
	def security_updates(self) -> tuple[Upgradable, ...]:
		return tuple(u for u in self.upgradable if u.is_security)


def parse_dpkg_log(text: str) -> list[PackageEvent]:
	"""Parse `/var/log/dpkg.log`.

	Keeps only the four verbs that mean the software on this machine changed.
	dpkg writes seven times as many `status` lines as `install` lines, and
	carrying those through would mean judging a thousand rows to find one.
	"""
	events = []
	for line in text.splitlines():
		match = _DPKG_LINE.match(line.strip())
		if not match:
			continue
		action = match.group("action")
		if action not in INTERESTING_ACTIONS:
			continue
		try:
			when = datetime.strptime(f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
		except ValueError:
			continue

		old = match.group("old") or ""
		new = match.group("new") or ""
		# On an install line the "old" column is the literal `<none>`.
		if old == "<none>":
			old = ""
		events.append(
			PackageEvent(
				when=when, action=action, package=match.group("package"), old_version=old, new_version=new
			)
		)
	return events


def parse_upgradable(text: str) -> list[Upgradable]:
	"""Parse `apt list --upgradable`.

	The pocket is the whole point. A package listed as
	`noble-updates,noble-security` is a security fix; one listed as
	`noble-updates` alone is a bug fix, and conflating them turns nine urgent
	things into twenty-five unremarkable ones.
	"""
	found = []
	for line in text.splitlines():
		match = _UPGRADABLE_LINE.match(line.strip())
		if not match:
			continue
		found.append(
			Upgradable(
				package=match.group("package"),
				installed=match.group("installed").strip(),
				candidate=match.group("candidate"),
				pockets=tuple(match.group("pockets").split(",")),
			)
		)
	return found


def collect_history(since: datetime | None = None, path: str = DPKG_LOG) -> tuple[list[PackageEvent], list[Surface]]:
	"""Package changes, optionally only those after `since`."""
	if not os.path.exists(path):
		return [], [Surface(KIND_HISTORY, path, True, "not present", 0)]

	try:
		with open(path, encoding="utf-8", errors="replace") as handle:
			events = parse_dpkg_log(handle.read())
	except OSError as exc:
		return [], [Surface(KIND_HISTORY, path, False, str(exc), 0)]

	if since:
		events = [event for event in events if event.when > since]
	return events, [Surface(KIND_HISTORY, path, True, "", len(events))]


def collect_upgradable() -> tuple[list[Upgradable], list[Surface]]:
	"""What apt says is waiting.

	Deliberately does NOT run `apt update` first. Refreshing the package lists
	takes network, takes a lock other things want, and is a change to the
	system made by a monitoring tool -- which this app does not do. It reports
	what the last refresh found, and a list that has gone stale is itself
	visible as updates that never change.
	"""
	try:
		result = subprocess.run(  # noqa: S603
			["apt", "list", "--upgradable"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=120,
			check=False,
			env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"},
		)
	except FileNotFoundError:
		return [], [Surface(KIND_UPDATES, "apt", True, "not a dpkg-based system", 0)]
	except (OSError, subprocess.SubprocessError) as exc:
		return [], [Surface(KIND_UPDATES, "apt", False, str(exc), 0)]

	if result.returncode != 0:
		reason = (result.stderr or "").strip().splitlines()
		return [], [Surface(KIND_UPDATES, "apt", False, reason[-1] if reason else f"exit {result.returncode}", 0)]

	found = parse_upgradable(result.stdout)
	return found, [Surface(KIND_UPDATES, "apt", True, "", len(found))]


def collect(since: datetime | None = None, first_seen: dict | None = None) -> Snapshot:
	events, history_surfaces = collect_history(since)
	upgradable, update_surfaces = collect_upgradable()
	return Snapshot(
		events=tuple(events),
		upgradable=tuple(upgradable),
		surfaces=tuple(history_surfaces + update_surfaces),
		first_seen=first_seen or {},
	)
