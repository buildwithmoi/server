# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Judging changes to who can log in.

Written against the incident's `mysqld` account: UID 1003, a bash shell, no
home directory, sitting in `/etc/passwd` for months and reading as the MariaDB
service account to anyone glancing at the file.

That shape is unusually easy to catch, and the rules here say why in three
independent ways — a service name carrying a login shell, a login shell with no
home directory, and a non-system UID nobody remembers creating. Any one of them
alone is worth a look; together they are not something a package does.

Frappe-free, like the persistence rules.
"""

from __future__ import annotations

from server.security import accounts
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "accounts"

APPEARED = "Appeared"
MODIFIED = "Modified"
DISAPPEARED = "Disappeared"

#: An account nobody has used in this long, still able to log in, is an
#: unnecessary way in rather than an incident.
STALE_DAYS = 90


def _describe(account: accounts.Account) -> str:
	return (
		f"uid={account.uid} gid={account.gid} shell={account.shell} "
		f"home={account.home} ({'exists' if account.home_exists else 'MISSING'}) "
		f"groups={', '.join(account.groups) or 'none'}"
	)


# ----------------------------------------------------------------------
# Accounts
# ----------------------------------------------------------------------


def judge_account(change_type: str, account: accounts.Account, previous: accounts.Account | None = None) -> list[Finding]:
	if change_type == APPEARED:
		return _appeared(account)
	if change_type == MODIFIED:
		return _modified(account, previous)
	return _disappeared(account)


def _appeared(account: accounts.Account) -> list[Finding]:
	findings = [
		Finding(
			CRITICAL,
			f"New account: {account.username}",
			_describe(account),
			"Accounts are not created by accident. If you did not add this one, do not delete it "
			"yet — check what it owns and what it has run first, then assume anything it could "
			"reach is compromised.",
			CATEGORY,
		)
	]
	findings.extend(shape_findings(account))
	return findings


def shape_findings(account: accounts.Account) -> list[Finding]:
	"""What is wrong with this account regardless of when it appeared.

	Kept separate so the same judgements can be applied to the whole account
	list on a first scan, when there is nothing to diff against but the shapes
	are just as wrong.
	"""
	findings = []

	if account.uid == 0 and account.username != "root":
		findings.append(
			Finding(
				CRITICAL,
				f"Second root account: {account.username}",
				_describe(account),
				"UID 0 is root, whatever the account is called. A second one is a backdoor with "
				"a friendly name — there is no configuration that legitimately needs it.",
				CATEGORY,
			)
		)

	looks_like_service = account.username.lower() in accounts.SERVICE_NAMES
	if looks_like_service and account.can_log_in:
		findings.append(
			Finding(
				CRITICAL,
				f"Service account with a login shell: {account.username}",
				_describe(account),
				"A real service account has /usr/sbin/nologin. This one is named after a daemon "
				"and can log in, which is the exact shape of the rogue `mysqld` account in the "
				"incident — chosen so it reads as MariaDB's own to anyone skimming /etc/passwd.",
				CATEGORY,
			)
		)

	if account.can_log_in and account.home and not account.home_exists:
		findings.append(
			Finding(
				HIGH,
				f"Login shell with no home directory: {account.username}",
				_describe(account),
				"An account meant for a person has somewhere to live. One that can log in and has "
				"no home was created to be a way in rather than to be used — the incident's rogue "
				"account had exactly this.",
				CATEGORY,
			)
		)

	# UID 0 is covered by the second-root rule above; saying it twice is noise.
	if account.can_log_in and account.is_system and account.uid != 0:
		findings.append(
			Finding(
				HIGH,
				f"System account can log in: {account.username}",
				_describe(account),
				f"UID {account.uid} is below {accounts.SYSTEM_UID_MAX}, which is the range packages "
				"use for daemons — and daemons do not need a shell.",
				CATEGORY,
			)
		)

	return findings


def _modified(account: accounts.Account, previous: accounts.Account | None) -> list[Finding]:
	if previous is None:
		return shape_findings(account)

	findings = []
	gained = set(account.groups) - set(previous.groups)
	privileged_gained = gained & set(accounts.PRIVILEGED_GROUPS)
	if privileged_gained:
		findings.append(
			Finding(
				CRITICAL,
				f"{account.username} was granted {', '.join(sorted(privileged_gained))}",
				f"Groups {', '.join(previous.groups) or 'none'} -> {', '.join(account.groups) or 'none'}",
				"This account can now become root. Confirm you granted it; if not, treat every "
				"action it has taken since as untrusted.",
				CATEGORY,
			)
		)

	if account.shell != previous.shell:
		severity = CRITICAL if account.can_log_in and not previous.can_log_in else HIGH
		findings.append(
			Finding(
				severity,
				f"Login shell changed for {account.username}",
				f"{previous.shell or 'none'} -> {account.shell or 'none'}",
				"Giving a shell to an account that did not have one is how a service account "
				"becomes a way in. Changing it the other way is usually hardening.",
				CATEGORY,
			)
		)

	if account.uid != previous.uid:
		findings.append(
			Finding(
				CRITICAL,
				f"UID changed for {account.username}",
				f"{previous.uid} -> {account.uid}",
				"A UID does not change on its own, and changing it reassigns everything that "
				"account owns.",
				CATEGORY,
			)
		)

	if (
		previous.password_status in (accounts.PASSWORD_NONE, accounts.PASSWORD_LOCKED)
		and account.password_status == accounts.PASSWORD_SET
	):
		findings.append(
			Finding(
				HIGH,
				f"Password set on {account.username}, which had none",
				f"{previous.password_status} -> {account.password_status}",
				"On a key-only host a password is a second way in that nobody is watching, and "
				"the one that brute force can reach.",
				CATEGORY,
			)
		)

	findings.extend(f for f in shape_findings(account) if f not in findings)
	return findings


def _disappeared(account: accounts.Account) -> list[Finding]:
	severity = CRITICAL if account.privileged else MEDIUM
	return [
		Finding(
			severity,
			f"Account removed: {account.username}",
			_describe(account),
			"Usually deliberate. An account that could become root disappearing without you "
			"removing it is not — it can be a way of covering tracks.",
			CATEGORY,
		)
	]


def judge_stale(account: accounts.Account, days_since_login: int | None) -> list[Finding]:
	"""An account nobody uses that could still be used."""
	if not account.can_log_in or days_since_login is None:
		return []
	if days_since_login < STALE_DAYS:
		return []
	return [
		Finding(
			MEDIUM,
			f"Unused account still has a shell: {account.username}",
			f"No login in {days_since_login} days. {_describe(account)}",
			"Not an incident — an unnecessary way in. Lock the shell or remove the account; the "
			"fewer accounts that can log in, the fewer there are to watch.",
			CATEGORY,
		)
	]


# ----------------------------------------------------------------------
# Keys
# ----------------------------------------------------------------------


def judge_key(change_type: str, key: accounts.Key, used_from: list[str] | None = None) -> list[Finding]:
	if change_type == APPEARED:
		where = ""
		if used_from:
			where = f" This fingerprint has already been used to log in from: {', '.join(used_from)}."
		return [
			Finding(
				CRITICAL,
				f"New SSH key for {key.account}: {key.fingerprint}",
				f"{key.key_type} in {key.path}, comment {key.comment or 'none'}."
				+ (f" Options: {key.options}" if key.options else "")
				+ where,
				"A key added to authorized_keys grants login without touching a password, and "
				"survives every password change. Confirm the fingerprint against the machine you "
				"think it belongs to — the comment is chosen by whoever made the key and proves "
				"nothing.",
				CATEGORY,
			)
		]
	if change_type == DISAPPEARED:
		return [
			Finding(
				MEDIUM,
				f"SSH key removed for {key.account}: {key.fingerprint}",
				f"{key.key_type}, comment {key.comment or 'none'}",
				"Usually key rotation. Worth confirming if you were not expecting it.",
				CATEGORY,
			)
		]
	return []


def judge_coverage(surfaces: list[accounts.Surface]) -> list[Finding]:
	"""What could not be read, and what that costs.

	`/etc/shadow` is the usual one, and losing it costs the "a password was set
	on an account that had none" check specifically. Naming the consequence
	rather than the file is what makes the finding actionable.
	"""
	blind = [s for s in surfaces if not s.readable and s.reason != "does not exist"]
	if not blind:
		return []

	paths = ", ".join(sorted({s.path for s in blind}))
	loses_passwords = any(s.kind == "passwords" for s in blind)
	consequence = (
		" Password status cannot be read, so an account gaining a password — a second way in that "
		"brute force can reach — will not be noticed."
		if loses_passwords
		else ""
	)
	return [
		Finding(
			HIGH,
			"Some account information could not be read",
			f"Unreadable: {paths}.{consequence}",
			"Give this app a NOPASSWD sudoers rule for a read-only helper, or accept the reduced "
			"coverage knowingly. What must not happen is the gap looking like a clean result.",
			CATEGORY,
		)
	]
