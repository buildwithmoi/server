# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What the filesystem findings mean, and what to do about each one.

Separated from the collector for the same reason `rules.py` is separated from
`persistence.py`: collecting is about the machine, judging is about the estate,
and the two change for different reasons. Nothing here touches frappe or the
database, so every judgement below is testable against a hand-built item with
no site, no root and no compromised host to borrow.

The severities mean what they say elsewhere in this app:

  Critical  wake someone
  High      look today
  Medium    look this week
  Info      recorded, not raised

The bar for Critical is deliberately high. The spec this was built from is
explicit that an alerting system which cries wolf on day three is worse than
none at all, and every rule here was checked against a real box before it was
given a severity: 21 setuid binaries, 2 modified conffiles, 2 ELF files in
/tmp, 0 world-writable system files. A rule that fires on any of those as
Critical would be wrong, and is not written that way.
"""

from __future__ import annotations

from server.security import filesystem
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "filesystem"

APPEARED = "Appeared"
MODIFIED = "Modified"
DISAPPEARED = "Disappeared"

#: Where a setuid binary is normal. Anywhere else is a finding on its own,
#: regardless of what the file is or who owns it -- /opt and /srv hold
#: vendor software, and vendor software with the setuid bit set is a decision
#: somebody should have made on purpose.
EXPECTED_SETUID_ROOTS = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/")


def _finding(severity: str, subject: str, detail: str, runbook: str) -> Finding:
	return Finding(severity, subject, detail, runbook, category=CATEGORY)


# ----------------------------------------------------------------------
# setuid and setgid
# ----------------------------------------------------------------------


def _bits(item: filesystem.Item) -> str:
	flags = []
	if item.detail.get("setuid"):
		flags.append("setuid")
	if item.detail.get("setgid"):
		flags.append("setgid")
	return " and ".join(flags) or "setuid"


def judge_setuid(change_type: str, item: filesystem.Item, previous_hash: str = "") -> list[Finding]:
	"""A change to the set of things that can become another user.

	This is the shortest list in the whole app -- twenty-one entries on a
	stock Ubuntu -- and it is short because every entry is a deliberate grant
	of privilege. That is what makes a single addition worth waking someone
	for, and it is why this rule needs no tuning period: there is no volume to
	tune away.
	"""
	owner = item.detail.get("owner", "")
	where = item.path or item.identifier

	if change_type == APPEARED:
		if not item.package_owned:
			return [
				_finding(
					CRITICAL,
					f"New {_bits(item)} binary owned by no package: {where}",
					f"{where} appeared with the {_bits(item)} bit set, owned by {owner}, and no "
					f"installed package claims it. A setuid binary is a standing grant of the "
					f"owner's privileges to whoever can run it.",
					"Do not delete it yet — it is evidence. Copy it somewhere safe, then work out "
					"what put it there: check the package manager's history, the shell history of "
					"every account that can write to that directory, and this app's own persistence "
					"and account findings around the same timestamp. If nobody can account for it, "
					"treat the host as compromised rather than removing the file and moving on.",
				)
			]
		return [
			_finding(
				MEDIUM,
				f"Package {item.package} added a {_bits(item)} binary: {where}",
				f"{where} appeared with the {_bits(item)} bit set and belongs to {item.package}, "
				f"so an install or upgrade is the likely cause.",
				"Check that an upgrade actually ran at that time — `grep install /var/log/dpkg.log` "
				"— and that this package was something you meant to have. Legitimate provenance is "
				"the common case here; it is recorded rather than ignored because the list of things "
				"that can escalate privilege should never grow without somebody noticing.",
			)
		]

	if change_type == MODIFIED:
		return [
			_finding(
				CRITICAL,
				f"A {_bits(item)} binary changed: {where}",
				f"The contents of {where} are no longer what they were "
				f"({previous_hash[:12] or 'unknown'} → {item.content_hash[:12]}). It is owned by "
				f"{item.package or 'no package'} and runs as {owner}.",
				"An upgrade explains this, and nothing else does. Confirm one happened: "
				"`grep ' upgrade ' /var/log/dpkg.log` around that time, and `dpkg --verify "
				f"{item.package}` to ask the package manager directly whether the file on disk is "
				"the one it shipped. If dpkg disagrees with the disk and no upgrade ran, a binary "
				"that grants privilege has been replaced — that is a full incident, not a file to "
				"restore.",
			)
		]

	if change_type == DISAPPEARED:
		return [
			_finding(
				MEDIUM,
				f"A {_bits(item)} binary is gone: {where}",
				f"{where} no longer exists. It belonged to {item.package or 'no package'}.",
				"Usually a package removal. Worth confirming, because removing a setuid binary is "
				"also how somebody removes the evidence of having replaced one.",
			)
		]

	return []


def shape_findings(item: filesystem.Item) -> list[Finding]:
	"""What is wrong with an item on its own terms, with nothing to compare to.

	Runs on the FIRST scan, when there is no history and the diff rules have
	nothing to say. That matters more here than it sounds: a host rebuilt from
	a compromised snapshot has the intruder's setuid binary in its very first
	baseline, where a change-detector would record it as normal and never
	mention it again.
	"""
	findings = []
	where = item.path or item.identifier

	if item.kind != filesystem.KIND_SETUID:
		return findings

	if not item.package_owned:
		findings.append(
			_finding(
				HIGH,
				f"{_bits(item).capitalize()} binary owned by no package: {where}",
				f"{where} carries the {_bits(item)} bit and no installed package claims it. This was "
				f"already present when monitoring started, so it is not known to be recent — which "
				f"is exactly why it is worth checking rather than assuming.",
				"Confirm you put it there. Software installed from source, or by a vendor script, "
				"legitimately produces this. If you cannot account for it, remember that a host "
				"rebuilt from a snapshot of a compromised machine carries the intruder's files into "
				"its first baseline looking perfectly normal.",
			)
		)

	if not any(where.startswith(root) for root in EXPECTED_SETUID_ROOTS):
		findings.append(
			_finding(
				HIGH,
				f"{_bits(item).capitalize()} binary outside the system directories: {where}",
				f"{where} has the {_bits(item)} bit set but does not live under "
				f"{', '.join(EXPECTED_SETUID_ROOTS)}. Privileged binaries in unusual places are "
				f"harder to notice and easier to leave behind.",
				"Decide whether it needs that bit at all. If it is vendor software, it usually does "
				"not, and `chmod u-s` is the whole fix.",
			)
		)

	owner = item.detail.get("owner", "")
	if item.detail.get("setuid") and owner and not owner.startswith("root:"):
		findings.append(
			_finding(
				CRITICAL,
				f"Setuid binary owned by {owner.split(':')[0]}, not root: {where}",
				f"{where} is setuid and owned by {owner}. Anyone who can run it gains that "
				f"account's privileges — and anyone who can WRITE it chooses what runs with them.",
				"Check who can write to the file and its directory. A setuid binary owned by a "
				"non-root account that account can also modify is a self-service privilege "
				"escalation, whether or not it was put there deliberately.",
			)
		)

	return findings


# ----------------------------------------------------------------------
# Package integrity
# ----------------------------------------------------------------------


def judge_package_integrity(items: list[filesystem.Item]) -> list[Finding]:
	"""dpkg disagreeing with the disk about a file it installed.

	THE ONE DISTINCTION THAT MAKES THIS USABLE. A conffile is a file the
	package manager EXPECTS an administrator to edit — nginx.conf and
	mariadb.cnf are both modified on this box, and both should be. A
	non-conffile is a file dpkg installed and nobody was ever supposed to
	touch. Treating those two the same produces either an alert on every
	well-run server or silence on a replaced binary; there is no threshold
	that fixes it, only this flag.
	"""
	findings = []
	changed = [i for i in items if not i.detail.get("conffile")]
	conffiles = [i for i in items if i.detail.get("conffile")]

	for item in changed:
		findings.append(
			_finding(
				CRITICAL,
				f"A file dpkg installed has been modified: {item.path}",
				f"{item.path} does not match the checksum recorded when its package was unpacked, "
				f"and it is not a configuration file — nothing was supposed to edit it.",
				"Identify the package with `dpkg -S` and reinstall it with "
				"`apt-get install --reinstall`, but read the file first: a modified system binary "
				"is how a backdoor survives a reboot, and reinstalling destroys the evidence of "
				"what was in it. Check the file's mtime against your own change history, and "
				"against this app's SSH and sudo records for the same window.",
			)
		)

	if conffiles:
		names = ", ".join(sorted(i.path for i in conffiles))
		findings.append(
			_finding(
				INFO,
				f"{len(conffiles)} package configuration file(s) differ from the shipped version",
				f"{names}. Configuration files are meant to be edited, so this is normal on any "
				f"server anyone has configured. Recorded so the list can be compared later.",
				"No action. Worth a glance if a file appears here that you do not remember editing.",
			)
		)

	return findings


# ----------------------------------------------------------------------
# Temp directories and world-writable files
# ----------------------------------------------------------------------


def judge_temp_binary(item: filesystem.Item) -> list[Finding]:
	"""A compiled binary sitting in a world-writable temp directory.

	Not "a file", not "an executable" — an ELF binary. On this box that filter
	is the difference between 734 findings and 2, and the 2 are answerable.
	"""
	where = item.path or item.identifier
	owner = item.detail.get("owner", "")

	if item.detail.get("setuid"):
		return [
			_finding(
				CRITICAL,
				f"Setuid binary in a temp directory: {where}",
				f"{where} is a compiled binary with the setuid bit set, owned by {owner}, in a "
				f"directory anyone can write to. There is no legitimate reason for this "
				f"combination to exist.",
				"Treat the host as compromised. Preserve the file and its timestamps before doing "
				"anything else, then look for how it got there and what ran it.",
			)
		]

	return [
		_finding(
			HIGH,
			f"Compiled binary in a temp directory: {where}",
			f"{where} is an ELF binary owned by {owner} in a world-writable directory. Build "
			f"systems and package installers do this legitimately; so does anything that has just "
			f"downloaded a payload and not yet moved it.",
			"Work out which. `lsof` will name the process if it is still running, the owner and "
			"mtime usually explain a build artefact, and `strings` on an unfamiliar binary is a "
			"quick way to tell a compiler's output from somebody's tool. If it is a build "
			"artefact, this will keep firing until it is cleaned up — which is itself a reason to "
			"clean it up.",
		)
	]


def judge_world_writable(item: filesystem.Item) -> list[Finding]:
	"""Something in a system directory that anyone can rewrite.

	Zero of these on a healthy box, which is what makes it worth having: no
	baseline to learn, no volume to tune, and a single result means something.
	"""
	where = item.path or item.identifier
	mode = item.detail.get("mode", "")

	if item.detail.get("executable"):
		return [
			_finding(
				CRITICAL,
				f"World-writable executable in a system directory: {where}",
				f"{where} ({mode}) can be rewritten by any account on the host, and it is "
				f"executable. Whoever edits it chooses what runs the next time anything invokes it.",
				f"`chmod o-w {where}` now, then find out how it got that way — the mode was set by "
				f"something, and an installer that does this once will do it again on the next "
				f"upgrade.",
			)
		]

	return [
		_finding(
			HIGH,
			f"World-writable file in a system directory: {where}",
			f"{where} ({mode}) can be rewritten by any account on the host.",
			f"`chmod o-w {where}`. If it is a configuration file, consider what reads it and with "
			f"what privileges — a world-writable config is a way to change a privileged program's "
			f"behaviour without touching the program.",
		)
	]


# ----------------------------------------------------------------------
# Coverage
# ----------------------------------------------------------------------


def judge_coverage(surfaces: list) -> list[Finding]:
	"""Where the sweep could not look, and what that specifically costs.

	Coverage is reported, never assumed. A directory that could not be read
	contributes nothing to the item list, which is indistinguishable from a
	directory with nothing in it — and the second is a reassuring answer to a
	question that was never actually asked.
	"""
	blind = [s for s in surfaces if not s.readable]
	if not blind:
		return []

	lost = sorted({s.kind for s in blind})
	paths = ", ".join(sorted({s.path or s.kind for s in blind}))
	consequences = {
		filesystem.KIND_SETUID: "new setuid binaries",
		filesystem.KIND_PACKAGE: "modified system binaries",
		filesystem.KIND_TEMP_BINARY: "binaries staged in temp directories",
		filesystem.KIND_WORLD_WRITABLE: "world-writable system files",
	}
	missed = ", ".join(consequences.get(kind, kind) for kind in lost)

	return [
		_finding(
			HIGH,
			"Part of the filesystem could not be swept",
			f"Could not read: {paths}. While that is true, this scan cannot report {missed}.",
			"Usually a permissions problem rather than an attack — the scan runs as the bench user, "
			"and some of what it wants to read is root-only. A NOPASSWD sudoers entry for a "
			"read-only helper is the normal fix. Until then, treat a clean filesystem report as "
			"covering less than it appears to.",
		)
	]
