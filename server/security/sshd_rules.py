# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Which SSH settings matter, and how much.

The incident behind this app began with `PasswordAuthentication yes` and was
noticed eight months later by the hosting provider, because the host had been
turned into a proxy. Both halves of that sentence are rules here: the way in,
and what the way in was used for.

Severity is assigned against a real stock Ubuntu 24.04 configuration, not
against an ideal one. Stock ships `passwordauthentication yes`,
`permitrootlogin prohibit-password`, `allowtcpforwarding yes`, `loglevel INFO`
and `x11forwarding yes` -- so a rule set that calls all five Critical produces
five Criticals on every unmodified server, and by the third one nobody reads
them. What is Critical here is what is both dangerous AND unusual; what is
merely dangerous-by-default is Medium, and says so.

The compositional rules are the interesting ones. `allowtcpforwarding yes` is
the default and usually fine. `gatewayports yes` alone is odd. Together they
are a host configured to forward traffic from anywhere to anywhere, which is
precisely what the breached server was being used for -- so the pair is judged
as a pair.
"""

from __future__ import annotations

from server.security import sshd
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "sshd"

#: Cipher, MAC and key-exchange substrings that are broken rather than merely
#: old. CBC ciphers are malleable, MD5 and SHA-1 MACs are forgeable, and
#: diffie-hellman-group1 is 1024-bit.
WEAK_CIPHERS = ("-cbc", "3des", "arcfour", "blowfish", "cast128")
WEAK_MACS = ("hmac-md5", "hmac-sha1", "umac-64-")
WEAK_KEX = ("diffie-hellman-group1-", "diffie-hellman-group14-sha1", "rsa1024-")

#: Below this, sshd stops recording the key fingerprint on an accepted login,
#: which is the field that answers "which key was used" after the fact.
GOOD_LOG_LEVELS = ("VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3")


def _finding(severity: str, subject: str, detail: str, runbook: str) -> Finding:
	return Finding(severity, subject, detail, runbook, category=CATEGORY)


def _yes(value: str) -> bool:
	return value.strip().lower() == "yes"


# ----------------------------------------------------------------------
# The way in
# ----------------------------------------------------------------------


def judge_authentication(snapshot: sshd.Snapshot) -> list[Finding]:
	"""How someone is allowed to prove who they are."""
	findings = []

	if _yes(snapshot.get("passwordauthentication")):
		findings.append(
			_finding(
				CRITICAL,
				"SSH accepts passwords",
				"`PasswordAuthentication` is yes, so any account with a password can be reached "
				"from anywhere by anyone willing to guess. This is the setting the intrusion this "
				"app was written after actually used.",
				"Set `PasswordAuthentication no` and `KbdInteractiveAuthentication no` in "
				"/etc/ssh/sshd_config.d/99-hardening.conf, confirm every account that needs access "
				"has a working key FIRST, then `sudo sshd -t` and reload. Keep your current session "
				"open and prove a second login works before closing it — this is the change that "
				"locks people out of their own server.",
			)
		)

	if _yes(snapshot.get("permitemptypasswords")):
		findings.append(
			_finding(
				CRITICAL,
				"SSH accepts empty passwords",
				"`PermitEmptyPasswords` is yes. Any account whose password field is blank can be "
				"logged into with no credential at all.",
				"Set `PermitEmptyPasswords no` immediately, then check `passwd -S -a` for accounts "
				"with no password — this app's account detector reports them as password status.",
			)
		)

	root = snapshot.get("permitrootlogin").strip().lower()
	if root == "yes":
		findings.append(
			_finding(
				CRITICAL,
				"Root can log in over SSH",
				"`PermitRootLogin` is yes. Combined with password authentication this is a single "
				"guess away from total control, and it removes the audit trail — every action is "
				"root's, with no record of which person that was.",
				"Set `PermitRootLogin no`. Administrators log in as themselves and use sudo, which "
				"is what makes this app's sudo command history worth having.",
			)
		)
	elif root in ("prohibit-password", "without-password"):
		findings.append(
			_finding(
				MEDIUM,
				"Root can log in over SSH with a key",
				f"`PermitRootLogin` is {root}. Passwords are refused, so this is not an open door — "
				f"but a root login still produces no record of which person it was.",
				"This is the Ubuntu default, so it is not evidence of anything. Consider "
				"`PermitRootLogin no` anyway: the accountability argument holds even when the "
				"authentication is strong.",
			)
		)

	if not snapshot.all("allowusers") and not snapshot.all("allowgroups"):
		findings.append(
			_finding(
				MEDIUM,
				"Every account on the host can log in over SSH",
				"Neither `AllowUsers` nor `AllowGroups` is set, so SSH access is granted to any "
				"account that exists — including service accounts created by packages, and any "
				"account an intruder adds.",
				"Add `AllowUsers` naming the humans who need it. This app's account detector "
				"reports new accounts, but an allow-list means a new account is not also a new way "
				"in while you are reading the alert.",
			)
		)

	return findings


def judge_matches(snapshot: sshd.Snapshot) -> list[Finding]:
	"""Conditional overrides, which `sshd -T` does not show.

	THE POINT OF THIS RULE. `sshd -T` evaluates Match blocks against an empty
	connection, so its output can say `passwordauthentication no` on a server
	that accepts passwords for one group. Somebody reading `sshd -T`, or a
	monitoring tool that only reads `sshd -T`, sees a hardened server. The
	config file is the only place the truth is visible.
	"""
	findings = []
	dangerous = {
		"passwordauthentication": ("yes", "accepts passwords"),
		"permitrootlogin": ("yes", "allows root to log in"),
		"permitemptypasswords": ("yes", "accepts empty passwords"),
	}

	for block in snapshot.match_blocks:
		for key, (bad_value, description) in dangerous.items():
			value = block.settings.get(key, "").strip().lower()
			if value != bad_value:
				continue
			globally = snapshot.get(key).strip().lower()
			contradiction = (
				f" The global setting is `{globally}`, so the effective configuration reported by "
				f"`sshd -T` does NOT show this."
				if globally and globally != bad_value
				else ""
			)
			findings.append(
				_finding(
					CRITICAL,
					f"A Match block {description}: {block.criteria}",
					f"sshd_config line {block.line_number} — `Match {block.criteria}` sets "
					f"`{key} {block.settings[key]}`.{contradiction}",
					"Decide whether that exception is still wanted, and by whom. A Match block is "
					"how a server stays hardened everywhere except the one place somebody needed it "
					"not to be — and it is invisible to every check that reads only `sshd -T`.",
				)
			)

	return findings


# ----------------------------------------------------------------------
# What the way in gets used for
# ----------------------------------------------------------------------


def judge_forwarding(snapshot: sshd.Snapshot) -> list[Finding]:
	"""Whether this host will carry traffic on someone else's behalf.

	This is the half of the incident that had consequences. The intrusion was
	not noticed because somebody logged in; it was noticed because the address
	started proxying and the provider complained.
	"""
	findings = []
	forwarding = _yes(snapshot.get("allowtcpforwarding", "yes"))
	gateway = _yes(snapshot.get("gatewayports"))
	tunnel = snapshot.get("permittunnel").strip().lower() not in ("", "no")

	if forwarding and gateway:
		findings.append(
			_finding(
				HIGH,
				"This host is configured to forward traffic from anywhere to anywhere",
				"`AllowTcpForwarding` is yes and `GatewayPorts` is yes. Together those let any "
				"account with SSH access bind a forwarded port on a public interface — which is "
				"the configuration of an open proxy, and is what the breached server this app was "
				"written after was being used as.",
				"Set `GatewayPorts no` unless you know which service needs it. If forwarding is "
				"not needed either, `AllowTcpForwarding no` closes the whole category; check this "
				"app's outbound connection records first to see what would break.",
			)
		)
	elif gateway:
		findings.append(
			_finding(
				MEDIUM,
				"Forwarded SSH ports can be bound on public interfaces",
				"`GatewayPorts` is yes. A forwarded port is reachable from outside the host rather "
				"than only from it.",
				"Set `GatewayPorts no` unless a specific service depends on it.",
			)
		)
	elif forwarding:
		findings.append(
			_finding(
				INFO,
				"SSH port forwarding is enabled",
				"`AllowTcpForwarding` is yes, which is the default and is what makes ordinary "
				"tunnelling work. Recorded rather than raised, because it is only interesting "
				"alongside something else.",
				"No action on its own. Worth revisiting if this host never needs tunnels.",
			)
		)

	if tunnel:
		findings.append(
			_finding(
				HIGH,
				"SSH can create network tunnel devices",
				f"`PermitTunnel` is {snapshot.get('permittunnel')}. This goes beyond forwarding a "
				f"port — it lets a client build a network interface on this host and route through "
				f"it.",
				"Set `PermitTunnel no` unless you deliberately run a VPN over SSH. Almost nobody "
				"does, and it is the difference between forwarding one port and joining a network.",
			)
		)

	if _yes(snapshot.get("permituserenvironment")):
		findings.append(
			_finding(
				HIGH,
				"Users can set environment variables through SSH",
				"`PermitUserEnvironment` is yes, so entries in `~/.ssh/environment` and options on "
				"an authorized key are applied to the session. `LD_PRELOAD` is an environment "
				"variable, which turns a writable authorized_keys file into code execution.",
				"Set `PermitUserEnvironment no`. It is off by default and there is rarely a reason "
				"to turn it on.",
			)
		)

	return findings


# ----------------------------------------------------------------------
# Whether anything will be visible afterwards
# ----------------------------------------------------------------------


def judge_logging(snapshot: sshd.Snapshot) -> list[Finding]:
	"""Whether sshd records enough to reconstruct what happened.

	This app reads sshd's log. What sshd chooses not to write, this app cannot
	report, so the log level is a dependency rather than a preference.
	"""
	level = snapshot.get("loglevel", "INFO").strip().upper()

	if level in ("QUIET", "FATAL", "ERROR"):
		return [
			_finding(
				HIGH,
				f"SSH is barely logging (LogLevel {level})",
				f"`LogLevel` is {level}, which suppresses the authentication messages this app's "
				f"entire SSH history is built from. Successful logins, failures and disconnections "
				f"will not be recorded, so the intrusion view will be empty and look reassuring.",
				"Set `LogLevel VERBOSE`. Anything below INFO means there is no record of who "
				"connected, and a security tool reading a silent log reports a quiet server.",
			)
		]

	if level not in GOOD_LOG_LEVELS:
		return [
			_finding(
				MEDIUM,
				f"SSH is not recording key fingerprints (LogLevel {level})",
				f"`LogLevel` is {level}. Logins are recorded, but the fingerprint of the key used "
				f"is not — so 'who logged in' can be answered and 'with which key' cannot. After a "
				f"key is found to be untrusted, that is the question that identifies what it "
				f"touched.",
				"Set `LogLevel VERBOSE`. It costs a slightly noisier auth log and is what "
				"populates the key fingerprint on this app's accepted-login records.",
			)
		]

	return []


def judge_crypto(snapshot: sshd.Snapshot) -> list[Finding]:
	"""Broken algorithms still on the accepted list.

	Only the genuinely broken ones. "Not the newest" is not a finding — this
	would otherwise fire on every server with a default configuration, which
	is how a crypto check becomes something people disable.
	"""
	findings = []
	checks = (
		("ciphers", WEAK_CIPHERS, "ciphers", "CBC-mode and legacy ciphers are malleable"),
		("macs", WEAK_MACS, "message authentication codes", "MD5 and SHA-1 MACs are forgeable"),
		("kexalgorithms", WEAK_KEX, "key exchange algorithms", "1024-bit groups are within reach"),
	)

	for key, weak, label, why in checks:
		offered = snapshot.get(key)
		if not offered:
			continue
		bad = sorted({a for a in offered.split(",") if any(w in a for w in weak)})
		if not bad:
			continue
		findings.append(
			_finding(
				MEDIUM,
				f"SSH offers weak {label}",
				f"{', '.join(bad)}. {why}.",
				f"Remove them by setting `{key.capitalize()}` explicitly to the modern list only. "
				f"Ubuntu's defaults are already reasonable, so a weak algorithm here usually means "
				f"somebody widened the list deliberately — which is worth understanding before "
				f"narrowing it again.",
			)
		)

	return findings


def judge_keys(snapshot: sshd.Snapshot) -> list[Finding]:
	"""Where sshd looks for authorized keys.

	A path outside the user's own home is a single file that grants access to
	an account, editable by whoever owns that path rather than by the account
	holder.
	"""
	findings = []
	for path in snapshot.all("authorizedkeysfile"):
		for entry in path.split():
			if entry.startswith("/") and "%h" not in entry:
				findings.append(
					_finding(
						HIGH,
						f"Authorized keys are read from a shared path: {entry}",
						f"`AuthorizedKeysFile` includes {entry}, which is an absolute path rather "
						f"than one inside each user's home. Whoever can write that file can add a "
						f"key for the accounts it applies to.",
						f"Confirm you set this up. Check who owns and can write {entry}, and check "
						f"its contents against the keys this app has recorded — a key in a global "
						f"file is one that never appears in a user's own authorized_keys.",
					)
				)
	return findings


def judge_effective_drift(previous_hash: str, snapshot: sshd.Snapshot) -> list[Finding]:
	"""The MERGED configuration changed, whatever the files say.

	This is the case the spec singled out, and it is not the same as a file
	changing: cloud-init rewrites its drop-in on some reboots and silently
	re-enables password authentication, and an OpenSSH upgrade can move a
	default with no file edit at all. Both change what sshd DOES while leaving
	the file somebody would think to check exactly as it was.

	The specific values are judged by the rules above every scan, so this
	reports the movement rather than the value — including a change to
	something no rule here has an opinion about yet.
	"""
	if not previous_hash or not snapshot.effective_hash or previous_hash == snapshot.effective_hash:
		return []

	return [
		_finding(
			HIGH,
			"The effective SSH configuration changed",
			f"The merged settings sshd is actually using are no longer what they were "
			f"({previous_hash[:12]} → {snapshot.effective_hash[:12]}). This is independent of the "
			f"config FILES, which are reported separately — a drop-in rewritten on reboot, or a "
			f"default moved by an upgrade, changes this without changing those.",
			"Compare against what you expect: `sudo sshd -T | sort`. Any authentication finding "
			"raised alongside this one says what actually moved. If nothing else was raised, "
			"something changed that this app has no rule about yet, which is worth reading anyway.",
		)
	]


def judge_drift(previous: dict, snapshot: sshd.Snapshot) -> list[Finding]:
	"""An SSH configuration file is not what it was.

	Reported per file rather than as one hash over everything, because "which
	file" is most of the answer. A change to `sshd_config` is usually a person;
	a NEW file appearing in `sshd_config.d` is how a setting gets overridden
	without the file anyone would look at being touched at all.

	Only the hashes are compared — never the contents. An sshd_config names
	bastion hosts, internal addresses and account names, and this app must not
	become the single richest target on the estate.
	"""
	if not previous:
		return []

	findings = []
	current = snapshot.file_hashes

	for path, digest in sorted(current.items()):
		was = previous.get(path)
		if was is None:
			findings.append(
				_finding(
					HIGH,
					f"A new SSH configuration file appeared: {path}",
					f"{path} did not exist at the last check. Files in {sshd.CONFIG_DIRECTORY} are "
					f"read before the body of the main config, and sshd takes the FIRST value it "
					f"sees for most keywords — so a new file here silently overrides the file "
					f"everyone would think to look at.",
					"Read it, and confirm you or a package put it there. Compare its settings "
					"against the effective configuration findings raised alongside this one.",
				)
			)
		elif was != digest:
			findings.append(
				_finding(
					HIGH,
					f"An SSH configuration file changed: {path}",
					f"Contents changed ({was[:12]} → {digest[:12]}). Only the hash is compared; the "
					f"file itself is never stored.",
					"If you changed it, no action. If you did not, find out what did — a package "
					"upgrade rewriting a default and somebody re-enabling password authentication "
					"look identical from here, and the settings findings raised alongside this "
					"will say which it was.",
				)
			)

	for path in sorted(set(previous) - set(current)):
		findings.append(
			_finding(
				HIGH,
				f"An SSH configuration file was removed: {path}",
				f"{path} existed at the last check and does not now. Whatever it configured has "
				f"reverted to the default, and several sshd defaults are permissive — "
				f"`PasswordAuthentication` defaults to yes.",
				"Check whether a hardening file was removed. The authentication findings raised "
				"alongside this report what the door actually does now.",
			)
		)

	return findings


def judge_coverage(surfaces: list) -> list[Finding]:
	"""Not being able to read the SSH configuration is itself the finding.

	This one matters more than most coverage gaps. If `sshd -T` cannot run,
	every rule above contributes nothing, and a report with no SSH findings
	reads exactly like a correctly configured server.
	"""
	blind = [s for s in surfaces if not s.readable]
	if not blind:
		return []

	effective_lost = any(s.kind == "sshd" for s in blind)
	paths = ", ".join(sorted({f"{s.path} ({s.reason})" for s in blind}))

	if effective_lost:
		return [
			_finding(
				HIGH,
				"The effective SSH configuration could not be read",
				f"Could not run `sshd -T`: {paths}. Every SSH setting check is therefore reporting "
				f"nothing — which is indistinguishable, in this app's own output, from a server "
				f"with nothing wrong.",
				"`sshd -T` reads the host private keys, so it needs root. A NOPASSWD sudoers entry "
				"for exactly `/usr/sbin/sshd -T` is the usual fix and grants nothing else. Until "
				"then, treat the absence of SSH findings as absence of evidence.",
			)
		]

	return [
		_finding(
			MEDIUM,
			"Part of the SSH configuration could not be read",
			f"Could not read: {paths}. Match blocks in those files are not being checked, so a "
			f"conditional override re-enabling password authentication would not be seen.",
			"Usually a permissions problem. The effective configuration is still being checked, so "
			"this is a partial gap rather than a blind spot.",
		)
	]


ALL_RULES = (
	judge_authentication,
	judge_matches,
	judge_forwarding,
	judge_logging,
	judge_crypto,
	judge_keys,
)


def judge(
	snapshot: sshd.Snapshot,
	previous_hashes: dict | None = None,
	previous_effective: str = "",
) -> list[Finding]:
	"""Every rule, in the order a person would want to read them.

	WHEN THE EFFECTIVE CONFIGURATION COULD NOT BE READ, THE SETTINGS RULES DO
	NOT RUN. Every one of them reaches for a value with a default — that is
	correct when sshd told us nothing about a keyword, and completely wrong
	when sshd told us nothing at all. Without this guard a host with no
	readable config reports "SSH is not recording key fingerprints" and "every
	account can log in over SSH" as though those had been observed, which is
	the same confident empty answer the coverage surfaces exist to prevent —
	and it buries the one finding that is actually true, that nothing could be
	read.

	The Match block and drift rules still run: both work from the config files,
	which are readable without root and are a genuinely separate source.
	"""
	findings: list[Finding] = []
	rules = ALL_RULES if snapshot.effective else (judge_matches,)
	for rule in rules:
		findings.extend(rule(snapshot))
	findings.extend(judge_drift(previous_hashes or {}, snapshot))
	findings.extend(judge_effective_drift(previous_effective, snapshot))
	findings.extend(judge_coverage(list(snapshot.surfaces)))
	return findings
