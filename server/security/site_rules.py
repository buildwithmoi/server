# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What the site's security state means.

The operating-system detectors in this package ask whether somebody got in.
These ask what they would find if they did -- and on an ordinary frappe bench
the answer is worse than it looks, because the credentials are sitting in
world-readable JSON rather than behind anything.

Severity here follows the same rule as everywhere else in this app: Critical
means the finding is both serious and specific enough to act on tonight.
"Frappe's defaults are not ideal" is not Critical, or every bench in the world
would page its owner on the day it was created. An exposed encryption key is,
because it is one `cat` away from every stored password on the site.
"""

from __future__ import annotations

from server.security import site
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "site"


def _finding(severity: str, subject: str, detail: str, runbook: str) -> Finding:
	return Finding(severity, subject, detail, runbook, category=CATEGORY)


def _short(path: str) -> str:
	"""The part of a path worth reading, without the bench prefix."""
	return path.split("/sites/", 1)[-1] if "/sites/" in path else path


# ----------------------------------------------------------------------
# Credentials on disk
# ----------------------------------------------------------------------


def judge_config_exposure(configs: list[site.ConfigFile]) -> list[Finding]:
	"""Configuration files that anyone on the host can read.

	WHY THE ENCRYPTION KEY IS THE POINT. `db_password` is bad and bounded --
	it reaches the database. `encryption_key` is what frappe uses to decrypt
	every `Password` field in the site, which in this app includes the database
	root password used for restores and the token used to forward findings off
	the box. Reading one file turns a local foothold into every credential the
	site holds, without touching the database at all.

	Reported as one finding per exposure class rather than one per file: a
	bench that has been running for a year has a sidecar for every backup it
	has ever taken, and three hundred identical Criticals is the same as none.
	"""
	findings = []
	exposed = [c for c in configs if c.exposes_secrets and c.path_traversable]
	if not exposed:
		return findings

	world = [c for c in exposed if c.world_readable]
	group_only = [c for c in exposed if not c.world_readable and c.group_readable]
	writable = [c for c in exposed if c.mode[-1] in "2367" or c.mode[-2] in "2367"]

	if world:
		keys = sorted({key for c in world for key in c.secret_keys})
		names = ", ".join(_short(c.path) for c in world[:5])
		more = f" and {len(world) - 5} more" if len(world) > 5 else ""
		findings.append(
			_finding(
				CRITICAL,
				f"{len(world)} configuration file(s) expose site credentials to every local account",
				f"{names}{more} are readable by any account on this host, and hold: {', '.join(keys)}. "
				f"`encryption_key` is the one that matters most — frappe decrypts every stored "
				f"password with it, so reading that file yields the database root password and the "
				f"forwarding token this app keeps, without touching the database.",
				"chmod 600 each file and 700 the directories above it. Frappe writes a copy of the "
				"site config beside every backup it takes, so this comes back on the next backup "
				"unless the backup directory itself is 700 — fixing the files without fixing the "
				"directory fixes it until tomorrow. Then treat the credentials as known: rotate the "
				"database password, and be aware that rotating `encryption_key` invalidates every "
				"`Password` field already stored, which is a migration rather than an edit.",
			)
		)

	if group_only:
		findings.append(
			_finding(
				HIGH,
				f"{len(group_only)} configuration file(s) expose site credentials to their group",
				f"{', '.join(_short(c.path) for c in group_only[:5])} are readable by the owning "
				f"group. Narrower than world-readable, and still wider than one account.",
				"chmod 640 → 600. Check who is actually in that group first; on a bench that runs "
				"web and worker processes as the same user this is usually an accident rather than "
				"a decision.",
			)
		)

	if writable:
		findings.append(
			_finding(
				CRITICAL,
				f"{len(writable)} configuration file(s) can be WRITTEN by someone other than the owner",
				f"{', '.join(f'{_short(c.path)} ({c.mode})' for c in writable[:5])}. Reading these "
				f"yields the credentials; writing them chooses what the site connects to.",
				"chmod 600 immediately. A writable site_config.json means somebody else picks the "
				"database host — which is a way to make the site hand its own data over on the "
				"next restart.",
			)
		)

	return findings


def judge_settings(configs: list[site.ConfigFile]) -> list[Finding]:
	"""Application settings that widen what anyone reaching the site can do."""
	findings = []
	# Only the live config, never the backup sidecars — those record what was
	# true when the backup was taken, and alerting on history is how a check
	# becomes permanent noise.
	live = [c for c in configs if c.path.endswith("site_config.json") and "backups" not in c.path]

	for config in live:
		name = _short(config.path)

		if config.settings.get("developer_mode"):
			findings.append(
				_finding(
					HIGH,
					f"Developer mode is on: {name}",
					"`developer_mode` is enabled. It permits Server Scripts — arbitrary Python "
					"executed by the application — and it switches on this app's own "
					"`get_context_for_dev` endpoint, which serves boot data to unauthenticated "
					"callers by design and is safe only because developer mode is normally off.",
					"Turn it off on anything reachable from outside: `bench --site <site> "
					"set-config developer_mode 0` then `bench --site <site> clear-cache`. If this "
					"IS a development machine, no action — but confirm it is not also reachable.",
				)
			)

		if config.settings.get("allow_tests"):
			findings.append(
				_finding(
					MEDIUM,
					f"The test runner is enabled: {name}",
					"`allow_tests` is true. Frappe's test runner truncates and rebuilds tables, so "
					"this is a switch that permits destroying the site's data through an ordinary "
					"command rather than a dangerous one.",
					"`bench --site <site> set-config allow_tests false` on anything holding real "
					"data. Leave it on for a development site.",
				)
			)

		if config.settings.get("server_script_enabled"):
			findings.append(
				_finding(
					HIGH,
					f"Server Scripts are enabled: {name}",
					"`server_script_enabled` allows Python stored in the database to be executed by "
					"the application. Anyone who can write a Server Script — or who reaches the "
					"database — can run code as the bench user.",
					"Disable it unless something depends on it. If something does, treat the "
					"Server Script list as code: review it, and know that this app's persistence "
					"detector does not see it, because it is not on the filesystem.",
				)
			)

	return findings


# ----------------------------------------------------------------------
# Backups
# ----------------------------------------------------------------------


def judge_backups(states: list[site.BackupState]) -> list[Finding]:
	"""Whether there is actually a way back.

	Backups fail silently. Nobody notices a cron that stopped until the day
	they need it, and that day is by definition the worst one — so "is there a
	recent one" is checked continuously rather than trusted.
	"""
	findings = []

	for state in states:
		if state.count == 0:
			findings.append(
				_finding(
					HIGH,
					f"No backups exist for {state.site}",
					f"There are no restorable backups in {state.site}'s own backup directory. "
					f"Whatever happens to this site, there is no way back from it.",
					"Run `bench --site <site> backup --with-files` now, then check that the backup "
					"cron is actually scheduled and succeeding — this app's disk alerting will tell "
					"you if backups start consuming the volume, but nothing else notices when they "
					"stop being taken at all.",
				)
			)
			continue

		if state.newest_age_hours is not None and state.newest_age_hours > site.BACKUP_STALE_HOURS:
			days = state.newest_age_hours / 24
			findings.append(
				_finding(
					HIGH,
					f"The newest backup for {state.site} is {days:.1f} days old",
					f"The most recent database backup is {state.newest_age_hours:.0f} hours old, "
					f"against a schedule that should produce one daily. There are {state.count} in "
					f"total, so backups worked once and stopped.",
					"Check the backup cron and the disk. A backup job that fails leaves the old "
					"files in place, so the directory looks healthy and the contents are stale — "
					"which is why this is measured by age rather than by count.",
				)
			)

		if not state.newest_has_files:
			findings.append(
				_finding(
					MEDIUM,
					f"The newest backup for {state.site} is database-only",
					"The most recent backup has no public or private files. Restoring it brings "
					"back every record and none of the attachments, which is discovered at the "
					"worst possible moment.",
					"Take backups with `--with-files`. It is slower and larger; it is also the "
					"difference between a restore and a partial one.",
				)
			)

		if state.config_sidecars:
			findings.append(
				_finding(
					INFO,
					f"{len(state.config_sidecars)} site-config copies sit beside {state.site}'s backups",
					"Frappe writes a copy of the site configuration next to every backup. Each one "
					"contains the database password and the encryption key. Whether that is a "
					"problem depends on their permissions, which are judged separately.",
					"No action on its own. If the exposure finding above is present, these are "
					"what it is mostly about — and there is one more of them after every backup.",
				)
			)

	return findings


# ----------------------------------------------------------------------
# Who can use the application
# ----------------------------------------------------------------------


def judge_accounts(accounts: dict) -> list[Finding]:
	"""Privileged users and long-lived credentials inside the site.

	Takes plain data rather than querying, so the judgement is testable
	without a database and the frappe-specific reading stays in one place.
	"""
	findings = []
	if not accounts:
		return findings

	managers = accounts.get("system_managers") or []
	if len(managers) > 3:
		findings.append(
			_finding(
				MEDIUM,
				f"{len(managers)} accounts hold System Manager",
				f"{', '.join(sorted(managers)[:8])}. System Manager can read every doctype, change "
				f"any setting, and — where Server Scripts are enabled — run code.",
				"Trim it to the people who need it. This is not a finding about any individual; it "
				"is that the number tends to grow and never shrink, and every one of them is a way "
				"in that has to be secured separately.",
			)
		)

	dormant = accounts.get("enabled_never_logged_in") or []
	if dormant:
		findings.append(
			_finding(
				MEDIUM,
				f"{len(dormant)} enabled account(s) have never logged in",
				f"{', '.join(sorted(dormant)[:8])}. An account nobody uses is an account nobody "
				f"notices being used.",
				"Disable them. If they exist for an integration, they should hold an API key and "
				"have interactive login disabled, rather than being ordinary users nobody watches.",
			)
		)

	keys = accounts.get("api_key_holders") or []
	if keys:
		findings.append(
			_finding(
				INFO,
				f"{len(keys)} account(s) hold API keys",
				f"{', '.join(sorted(keys)[:8])}. An API key is a credential that does not expire, "
				f"is not rotated by a password policy, and is often pasted into a config file "
				f"somewhere else.",
				"Recorded so the list can be compared later. Worth checking that each one is still "
				"used and that its account is not also a System Manager.",
			)
		)

	if accounts.get("administrator_enabled") and accounts.get("administrator_has_password"):
		findings.append(
			_finding(
				MEDIUM,
				"The Administrator account is enabled and has a password",
				"Administrator bypasses permission checks entirely. A password on it is a way into "
				"the site that no role restricts, and its actions are attributed to nobody in "
				"particular.",
				"Use named System Manager accounts for day-to-day work. Keep Administrator for "
				"recovery, with a password nobody has memorised and this app's SSH and sudo "
				"records to show who used the machine when it was needed.",
			)
		)

	return findings


def judge_coverage(surfaces: list) -> list[Finding]:
	"""What could not be read, and what that costs."""
	blind = [s for s in surfaces if not s.readable]
	if not blind:
		return []

	paths = ", ".join(sorted({f"{s.path} ({s.reason})" for s in blind}))
	return [
		_finding(
			MEDIUM,
			"Part of the site's security state could not be read",
			f"Could not read: {paths}. Credential exposure and backup recency are only reported "
			f"for what could be opened.",
			"Usually a permissions problem, and worth fixing rather than ignoring: the files this "
			"check cannot read are the ones holding the credentials.",
		)
	]


ALL_RULES = (judge_config_exposure, judge_settings, judge_backups, judge_accounts)


def judge(snapshot: site.Snapshot) -> list[Finding]:
	findings: list[Finding] = []
	findings.extend(judge_config_exposure(list(snapshot.configs)))
	findings.extend(judge_settings(list(snapshot.configs)))
	findings.extend(judge_backups(list(snapshot.backups)))
	findings.extend(judge_accounts(snapshot.accounts))
	findings.extend(judge_coverage(list(snapshot.surfaces)))
	return findings
