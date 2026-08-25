# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Judging what this host is listening on and talking to.

The specification asks for "outbound connection to port 22 on an external host
→ Critical", because SSH brute-force leaving this address is the reported abuse
that got it blocked. Taken literally that rule is wrong here, and the box
proved it within a minute of the collector being written: there was a live
outbound connection to port 22, from `git`, because `bench get-app` and
`git pull` fetch private apps over SSH. That is this app's own core workflow.

So the rule is split. Port 22 to a host we deliberately clone from is normal
and silent. Port 22 to anywhere else is Critical. And port 22 to MANY distinct
destinations is Critical whatever they are, because that is not fetching a
repository, that is the brute force itself — and it is the shape the thirty-
seven abuse reports described.

That distinction is the difference between a detector someone keeps switched on
and one they mute in week two.

Frappe-free.
"""

from __future__ import annotations

from server.security import network
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "network"

#: Hosts this estate legitimately clones from over SSH. Held as data so adding
#: a self-hosted git server is a configuration change, not a code change.
GIT_HOSTS = (
	"github.com", "gitlab.com", "bitbucket.org", "ssh.github.com", "altssh.gitlab.com",
)

#: More distinct port-22 destinations than this in one window is not fetching
#: code. Deliberately low: a bench pulls from one or two hosts.
SSH_FANOUT_LIMIT = 3

#: Distinct external destinations in one scan beyond which the host looks like
#: it is scanning or proxying rather than serving.
FANOUT_LIMIT = 40

#: Consecutive scans seeing SYN-SENT to the same endpoint before it is called a
#: beacon. One is a slow DNS lookup; three is something retrying.
BEACON_SCANS = 3

#: Software with no legitimate reason to exist on an ERPNext host.
KNOWN_BAD = (
	"xmrig", "microsocks", "x-ui", "xray", "v2ray", "shadowsocks", "frpc", "frps",
	"kdevtmpfsi", "kinsing", "masscan", "zmap", "hydra", "medusa",
)


def _describes(socket: network.Socket) -> str:
	who = socket.binary or (f"{socket.process} (self-reported name, binary unreadable)" if socket.process else "unknown process")
	return f"{socket.protocol}/{socket.remote_port} to {socket.remote_address}, by {who} (pid {socket.pid or '?'})"


def _mentions_known_bad(text: str) -> str:
	lowered = (text or "").lower()
	return next((name for name in KNOWN_BAD if name in lowered), "")


# ----------------------------------------------------------------------
# Outbound
# ----------------------------------------------------------------------


def judge_outbound(
	sockets: list[network.Socket],
	allowed_ports: tuple[int, ...] = network.DEFAULT_ALLOWED_PORTS,
	git_host_addresses: tuple[str, ...] = (),
) -> list[Finding]:
	"""What is leaving this host that should not be."""
	findings: list[Finding] = []
	external = [s for s in sockets if s.remote_is_external and s.state != network.STATE_LISTEN]

	ssh_destinations = {s.remote_address for s in external if s.remote_port == network.SSH_PORT}
	unexpected_ssh = ssh_destinations - set(git_host_addresses)

	# Fan-out first: many SSH destinations is the brute force, whoever they are.
	if len(ssh_destinations) > SSH_FANOUT_LIMIT:
		findings.append(
			Finding(
				CRITICAL,
				f"Outbound SSH to {len(ssh_destinations)} different hosts",
				f"Destinations: {', '.join(sorted(ssh_destinations)[:12])}"
				+ ("…" if len(ssh_destinations) > 12 else ""),
				"Fetching code reaches one or two hosts. Reaching many is the SSH brute-force "
				"that thirty-seven parties reported coming out of this estate's address, and it "
				"is what gets an address blocked. Find the process before killing it.",
				CATEGORY,
			)
		)
	else:
		for address in sorted(unexpected_ssh):
			socket = next(s for s in external if s.remote_address == address and s.remote_port == network.SSH_PORT)
			findings.append(
				Finding(
					CRITICAL,
					f"Outbound SSH to {address}",
					_describes(socket),
					"A web server has no reason to SSH out, except to the hosts it clones apps "
					f"from ({', '.join(GIT_HOSTS[:3])}…). If this is a git remote you added, add "
					"it to the allowed hosts. If it is not, this is the reported abuse.",
					CATEGORY,
				)
			)

	seen_ports: set[tuple[str, int]] = set()
	for socket in external:
		if socket.remote_port in allowed_ports or socket.remote_port == network.SSH_PORT:
			continue
		key = (socket.remote_address, socket.remote_port)
		if key in seen_ports:
			continue
		seen_ports.add(key)
		findings.append(
			Finding(
				CRITICAL,
				f"Outbound connection to an unexpected port: {socket.remote_address}:{socket.remote_port}",
				_describes(socket),
				"This host needs DNS, HTTP, HTTPS, mail submission and NTP. Anything else leaving "
				"it is either an integration nobody wrote down — in which case add the port — or "
				"something talking to an endpoint of its own choosing.",
				CATEGORY,
			)
		)

	destinations = {s.remote_address for s in external}
	if len(destinations) > FANOUT_LIMIT:
		findings.append(
			Finding(
				HIGH,
				f"Connections to {len(destinations)} distinct external addresses",
				f"Sample: {', '.join(sorted(destinations)[:10])}…",
				"A server serving web pages talks to a handful of places. Talking to many at once "
				"is the shape of scanning, or of carrying somebody else's traffic — which is what "
				"the proxy software in the incident was doing.",
				CATEGORY,
			)
		)

	findings.extend(_judge_processes_on_sockets(external))
	return findings


def _judge_processes_on_sockets(sockets: list[network.Socket]) -> list[Finding]:
	reported: set[str] = set()
	findings = []
	for socket in sockets:
		haystack = f"{socket.process} {socket.binary}"
		match = _mentions_known_bad(haystack)
		if match and match not in reported:
			reported.add(match)
			findings.append(
				Finding(
					CRITICAL,
					f"Known proxy or mining software has a network connection: {match}",
					_describes(socket),
					"This is proxy, tunnelling or mining software. On an ERPNext host none of it "
					"has a legitimate reason to exist, and it is what generates the outbound "
					"abuse that gets an address blocked. Preserve the binary before killing it.",
					CATEGORY,
				)
			)
	return findings


def judge_beacons(persistent: dict[tuple[str, int], int]) -> list[Finding]:
	"""Endpoints this host keeps trying to reach and cannot.

	`SYN-SENT` that never becomes established is the clearest single signal
	here. The incident's beacon to 130.12.180.50:4433 was visible in exactly
	this state, retrying forever, because the address had already been blocked
	— the malware kept calling home long after anyone was listening.
	"""
	findings = []
	for (address, port), scans in sorted(persistent.items()):
		if scans < BEACON_SCANS:
			continue
		findings.append(
			Finding(
				CRITICAL,
				f"Repeatedly trying to reach {address}:{port}",
				f"Seen in SYN-SENT on {scans} consecutive scans without connecting.",
				"Something on this host keeps calling an address that is not answering. On a "
				"healthy server that does not happen — a failed integration retries and gives up. "
				"This is what a beacon looks like once its destination has been blocked, which is "
				"how the incident's was eventually noticed.",
				CATEGORY,
			)
		)
	return findings


# ----------------------------------------------------------------------
# Listening
# ----------------------------------------------------------------------


def judge_new_listener(socket: network.Socket) -> list[Finding]:
	"""A port that was not open at the last scan."""
	where = "on every interface" if socket.listening_publicly else f"on {socket.local_address}"
	notorious = network.NOTORIOUS_LISTEN_PORTS.get(socket.local_port)

	severity = CRITICAL if (socket.listening_publicly or notorious) else HIGH
	detail = (
		f"{socket.protocol}/{socket.local_port} {where}, by "
		f"{socket.binary or socket.process or 'a process that could not be identified'}"
	)
	runbook = (
		"Check what opened it. A bench opens its web, socketio and redis ports and nothing else; "
		"anything beyond that was started by something you did not deploy."
	)
	if notorious:
		detail += f". Port {socket.local_port} is {notorious}."
		runbook = (
			f"Port {socket.local_port} is {notorious}. That is not something an ERPNext host "
			"opens by accident — find the process and preserve its binary."
		)

	return [Finding(severity, f"New listening port: {socket.protocol}/{socket.local_port}", detail, runbook, CATEGORY)]


def judge_listener_gone(socket: network.Socket) -> list[Finding]:
	return [
		Finding(
			INFO,
			f"Port no longer listening: {socket.protocol}/{socket.local_port}",
			f"Was on {socket.local_address}, by {socket.binary or socket.process or 'unknown'}",
			"Usually a service being stopped or restarted.",
			CATEGORY,
		)
	]


# ----------------------------------------------------------------------
# Processes
# ----------------------------------------------------------------------


def judge_process(process: network.Process) -> list[Finding]:
	"""What is wrong with a running process, independent of the network."""
	findings = []

	if process.deleted_binary:
		findings.append(
			Finding(
				CRITICAL,
				f"Process running from a deleted binary: pid {process.pid}",
				f"Was {process.binary}, user {process.user or 'unknown'}. Command: {process.cmdline[:200]}",
				"The file is gone and the process is still running it — you cannot inspect the "
				"binary on disk because there is nothing there to inspect. This is standard "
				"practice for a payload that wants to survive being found, and it almost never "
				"happens by accident. Capture /proc/<pid>/exe before killing it; that handle is "
				"the only copy left.",
				CATEGORY,
			)
		)

	path = process.binary or ""
	if path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
		findings.append(
			Finding(
				CRITICAL,
				f"Process running from a temporary directory: {path}",
				f"pid {process.pid}, user {process.user or 'unknown'}. Command: {process.cmdline[:200]}",
				"Nothing legitimate is installed into /tmp. These directories are writable by "
				"everyone, which is exactly why a payload lands there.",
				CATEGORY,
			)
		)

	match = _mentions_known_bad(f"{path} {process.cmdline}")
	if match:
		findings.append(
			Finding(
				CRITICAL,
				f"Known proxy or mining software is running: {match}",
				f"pid {process.pid}, binary {path or 'unreadable'}. Command: {process.cmdline[:200]}",
				"Proxy, tunnelling or mining software has no legitimate place on an ERPNext host. "
				"Preserve the binary before killing the process.",
				CATEGORY,
			)
		)
	return findings


# ----------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------


def judge_firewall(previous_hash: str, snapshot: network.Snapshot, expect_output_drop: bool = False) -> list[Finding]:
	"""The egress lock is the control that makes the promise to the provider
	true, so its silent removal must not be possible."""
	findings = []

	if previous_hash and snapshot.firewall_hash and previous_hash != snapshot.firewall_hash:
		findings.append(
			Finding(
				HIGH,
				"Firewall ruleset changed",
				f"Ruleset hash {previous_hash[:12]} -> {snapshot.firewall_hash[:12]}",
				"If you did not change it, something else did. The egress rules are what stop "
				"this host carrying traffic on someone else's behalf, and removing them quietly "
				"is the first thing worth doing after getting in.",
				CATEGORY,
			)
		)

	if expect_output_drop and snapshot.firewall_hash and snapshot.firewall_output_policy not in ("drop", "reject"):
		findings.append(
			Finding(
				HIGH,
				"Outbound traffic is no longer being filtered by default",
				f"OUTPUT policy is {snapshot.firewall_output_policy or 'unknown'}, expected drop.",
				"This host is configured to expect a default-deny egress policy and does not have "
				"one. Until it does, anything running here can reach anywhere.",
				CATEGORY,
			)
		)
	return findings


def judge_coverage(surfaces: list[network.Surface]) -> list[Finding]:
	blind = [s for s in surfaces if not s.readable and s.reason != "does not exist"]
	if not blind:
		return []

	firewall_blind = any(s.kind == "firewall" for s in blind)
	detail = "; ".join(f"{s.path}: {s.reason}" for s in blind)
	consequence = (
		" The firewall ruleset cannot be read at all, so its removal would not be noticed."
		if firewall_blind
		else ""
	)
	return [
		Finding(
			HIGH,
			"Some network information could not be read",
			detail + consequence,
			"Process attribution and the firewall both need privilege. Without it a socket can be "
			"seen but not traced to the binary that opened it — which is the part that matters, "
			"because a process names itself. A NOPASSWD sudoers rule for a read-only helper "
			"closes this.",
			CATEGORY,
		)
	]
