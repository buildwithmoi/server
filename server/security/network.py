# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What this host is listening on, and what it is talking to.

This is the detector for the part of the incident that had consequences. The
miner, the SOCKS proxy and the x-ui panel were not just running — they were
carrying other people's traffic, and thirty-seven independent parties reported
SSH brute-force coming OUT of this address. None of it required an attacker
login, so nothing built on authentication events could see any of it.

An ERPNext host makes this practical in a way it would not be on a laptop. The
legitimate outbound set is tiny and enumerable — DNS, HTTP, HTTPS, mail
submission, NTP, and whatever payment or SMS API the sites call — so a
connection outside it is worth reading rather than worth tuning out. Outbound
port 22 in particular has no business leaving a server whose job is serving
web pages, and it is the exact traffic that got the address blocked.

THE PROCESS NAME IS NOT EVIDENCE. `ss` reports the name a process chose for
itself, which is one `prctl` call away from saying "nginx". The binary is read
from `/proc/<pid>/exe`, which the kernel maintains, and every record says which
of the two it managed to get — an unverified name is still useful, but it must
not be presented as though it were the path.

Frappe-free.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field

# ----------------------------------------------------------------------
# The egress policy, as data
# ----------------------------------------------------------------------

#: What a Frappe/ERPNext host legitimately needs to reach. Held as data so it
#: can be widened for a payment or SMS API without touching the rules.
DEFAULT_ALLOWED_PORTS = (
	53,     # DNS
	80,     # HTTP
	123,    # NTP
	443,    # HTTPS
	465,    # SMTPS
	587,    # SMTP submission
	993,    # IMAPS
	995,    # POP3S
)

#: Leaving this host, this is the reported abuse itself.
SSH_PORT = 22

#: Ports a payload commonly listens on, worth naming when one appears.
NOTORIOUS_LISTEN_PORTS = {
	1080: "SOCKS proxy",
	3128: "HTTP proxy",
	4433: "the beacon port in this estate's incident",
	5555: "commonly a remote-access backdoor",
	54321: "x-ui / Xray panel default",
	2375: "unauthenticated Docker API",
	6379: "Redis, which must never be public",
	9001: "commonly a mining pool proxy",
}

#: Anything not on the loopback or a private range is the outside world.
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fe80:", "fc", "fd")

#: Directories a legitimate daemon does not run from.
SUSPICIOUS_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/opt/", "/home/")
_HIDDEN_COMPONENT = re.compile(r"/\.[^/]")

#: `ss` renders the owning processes as
#: `users:(("name",pid=123,fd=8),("other",pid=124,fd=9))`.
_USERS = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')

STATE_LISTEN = "LISTEN"
STATE_SYN_SENT = "SYN-SENT"


@dataclass(frozen=True)
class Socket:
	"""One listening socket or one connection."""

	protocol: str
	state: str
	local_address: str
	local_port: int
	remote_address: str = ""
	remote_port: int = 0
	process: str = ""
	pid: int = 0
	#: From /proc/<pid>/exe. Empty when it could not be read.
	binary: str = ""
	#: False when only the self-reported name was available.
	binary_verified: bool = False

	@property
	def listening_publicly(self) -> bool:
		return self.state == STATE_LISTEN and self.local_address in ("0.0.0.0", "*", "::", "[::]")

	@property
	def remote_is_external(self) -> bool:
		return bool(self.remote_address) and not is_private(self.remote_address)

	def as_dict(self) -> dict:
		return {
			**self.__dict__,
			"listening_publicly": self.listening_publicly,
			"remote_is_external": self.remote_is_external,
		}


@dataclass(frozen=True)
class Process:
	"""One running process, as the kernel describes it."""

	pid: int
	ppid: int = 0
	user: str = ""
	binary: str = ""
	cmdline: str = ""
	#: True when /proc/<pid>/exe points at a file that no longer exists — a
	#: standard way of running something after deleting it, and close to a
	#: zero-false-positive signal on a server.
	deleted_binary: bool = False
	binary_readable: bool = True

	def as_dict(self) -> dict:
		return self.__dict__.copy()


@dataclass(frozen=True)
class Surface:
	kind: str
	path: str
	readable: bool
	reason: str = ""
	items_found: int = 0

	def as_dict(self) -> dict:
		return self.__dict__.copy()


@dataclass(frozen=True)
class Snapshot:
	sockets: list[Socket] = field(default_factory=list)
	processes: list[Process] = field(default_factory=list)
	surfaces: list[Surface] = field(default_factory=list)
	firewall_hash: str = ""
	firewall_output_policy: str = ""

	@property
	def blind_spots(self) -> list[Surface]:
		return [s for s in self.surfaces if not s.readable and s.reason != "does not exist"]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def is_private(address: str) -> bool:
	"""Is this address on this machine or on the local network?

	`ipaddress` first, because it gets 172.16/12 right and a string prefix does
	not — 172.16.0.1 is private while 172.32.0.1 is not, and a naive "172."
	check would quietly excuse a real external destination.

	NOTE FOR TESTS: `is_private` is true for the documentation ranges as well —
	203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24. That is correct (they are
	not routable) but it means a test written with those addresses silently
	exercises the internal path and passes without proving anything. Use real
	routable addresses when testing an external destination.
	"""
	import ipaddress

	cleaned = address.strip("[]")
	try:
		parsed = ipaddress.ip_address(cleaned)
	except ValueError:
		return cleaned.startswith(_PRIVATE_PREFIXES)
	return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified


def split_address(value: str) -> tuple[str, int]:
	"""Split `ss`'s address:port, including the bracketed IPv6 form."""
	value = value.strip()
	if value.startswith("["):
		host, _, port = value.rpartition("]:")
		return host.lstrip("["), _port(port)
	host, _, port = value.rpartition(":")
	return (host or value), _port(port)


def _port(value: str) -> int:
	try:
		return int(value)
	except ValueError:
		return 0


def binary_of(pid: int) -> tuple[str, bool, bool]:
	"""(path, readable, deleted) for a pid, from /proc.

	Reading another user's `exe` needs privilege, so on a host where this app
	runs as the bench user most processes come back unreadable. That is
	reported rather than silently treated as "no binary".
	"""
	try:
		target = os.readlink(f"/proc/{pid}/exe")
	except PermissionError:
		return "", False, False
	except OSError:
		return "", True, False

	if target.endswith(" (deleted)"):
		return target[: -len(" (deleted)")], True, True
	return target, True, False


def _run(argv: list[str], timeout: int = 30) -> tuple[int, str, str]:
	try:
		result = subprocess.run(  # noqa: S603
			argv,
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=timeout,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		return 1, "", str(exc)
	return result.returncode, result.stdout, result.stderr


# ----------------------------------------------------------------------
# Sockets
# ----------------------------------------------------------------------


def parse_ss(output: str, protocol: str) -> list[Socket]:
	"""Parse `ss -H` output.

	Hand-parsed because this `ss` has no JSON mode: the columns are
	`State Recv-Q Send-Q Local Peer [users:(...)]`, and the process column is
	absent entirely for sockets owned by another user.
	"""
	sockets: list[Socket] = []
	for raw in output.splitlines():
		line = raw.strip()
		if not line:
			continue
		parts = line.split(None, 5)
		if len(parts) < 5:
			continue

		state, _recvq, _sendq, local, peer = parts[:5]
		process_blob = parts[5] if len(parts) > 5 else ""
		local_address, local_port = split_address(local)
		remote_address, remote_port = split_address(peer)

		owners = _USERS.findall(process_blob)
		if not owners:
			sockets.append(
				Socket(
					protocol=protocol,
					state=state,
					local_address=local_address,
					local_port=local_port,
					remote_address="" if remote_address in ("0.0.0.0", "*", "[::]") else remote_address,
					remote_port=remote_port,
				)
			)
			continue

		# One socket can be held by many processes — gunicorn's workers share a
		# listener. The first is enough to attribute it.
		name, pid = owners[0]
		binary, readable, _deleted = binary_of(int(pid))
		sockets.append(
			Socket(
				protocol=protocol,
				state=state,
				local_address=local_address,
				local_port=local_port,
				remote_address="" if remote_address in ("0.0.0.0", "*", "[::]") else remote_address,
				remote_port=remote_port,
				process=name,
				pid=int(pid),
				binary=binary,
				binary_verified=bool(binary) and readable,
			)
		)
	return sockets


def collect_sockets() -> tuple[list[Socket], list[Surface]]:
	"""Listening sockets and live connections, TCP and UDP."""
	sockets: list[Socket] = []
	surfaces: list[Surface] = []

	probes = (
		(["ss", "-tlnpH"], "tcp", "listening"),
		(["ss", "-ulnpH"], "udp", "listening"),
		# `-a` so SYN-SENT is included: a beacon whose destination is blocked
		# never reaches ESTABLISHED, and sits retrying in exactly that state.
		(["ss", "-tnpHa"], "tcp", "connections"),
	)
	for argv, protocol, label in probes:
		code, out, err = _run(argv)
		if code != 0:
			surfaces.append(Surface("sockets", " ".join(argv), False, (err or "").strip()[:120]))
			continue
		found = parse_ss(out, protocol)
		sockets.extend(found)
		surfaces.append(Surface("sockets", label, True, items_found=len(found)))

	unattributed = sum(1 for s in sockets if s.pid and not s.binary_verified)
	if unattributed:
		surfaces.append(
			Surface(
				"sockets",
				"/proc/<pid>/exe",
				False,
				f"{unattributed} sockets could only be attributed by self-reported process name",
			)
		)
	return sockets, surfaces


# ----------------------------------------------------------------------
# Processes
# ----------------------------------------------------------------------


def collect_processes() -> tuple[list[Process], list[Surface]]:
	"""Every process, with the binary the kernel says it is running."""
	processes: list[Process] = []
	unreadable = 0

	try:
		pids = [name for name in os.listdir("/proc") if name.isdigit()]
	except OSError as exc:
		return [], [Surface("processes", "/proc", False, str(exc))]

	for entry in pids:
		pid = int(entry)
		binary, readable, deleted = binary_of(pid)
		if not readable:
			unreadable += 1

		processes.append(
			Process(
				pid=pid,
				ppid=_ppid(pid),
				user=_owner(pid),
				binary=binary,
				cmdline=_cmdline(pid),
				deleted_binary=deleted,
				binary_readable=readable,
			)
		)

	surfaces = [Surface("processes", "/proc", True, items_found=len(processes))]
	if unreadable:
		surfaces.append(
			Surface(
				"processes",
				"/proc/<pid>/exe",
				False,
				f"{unreadable} processes belong to other users, so their binary could not be read",
			)
		)
	return processes, surfaces


def _cmdline(pid: int) -> str:
	try:
		with open(f"/proc/{pid}/cmdline", "rb") as handle:
			return handle.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()[:500]
	except OSError:
		return ""


def _ppid(pid: int) -> int:
	try:
		with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as handle:
			for line in handle:
				if line.startswith("PPid:"):
					return int(line.split()[1])
	except (OSError, ValueError, IndexError):
		pass
	return 0


def _owner(pid: int) -> str:
	try:
		import pwd

		return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
	except (OSError, KeyError):
		return ""


# ----------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------


def collect_firewall() -> tuple[str, str, list[Surface]]:
	"""(ruleset hash, OUTPUT policy, coverage).

	The egress lock is the control that makes "this cannot happen again" true
	for the provider, so its silent removal must not be possible. Hashed rather
	than stored: a ruleset can name internal addresses.
	"""
	import hashlib

	for argv in (["nft", "list", "ruleset"], ["iptables", "-S"]):
		code, out, err = _run(argv)
		if code != 0:
			continue
		policy = ""
		match = re.search(r"chain\s+output\b[^{]*{[^}]*?policy\s+(\w+)", out, re.IGNORECASE | re.DOTALL)
		if match:
			policy = match.group(1).lower()
		elif "-P OUTPUT" in out:
			policy = out.split("-P OUTPUT")[1].split()[0].lower()
		return (
			hashlib.sha256(out.encode()).hexdigest(),
			policy,
			[Surface("firewall", argv[0], True, items_found=len(out.splitlines()))],
		)

	return "", "", [Surface("firewall", "nft/iptables", False, "not readable without root")]


def collect() -> Snapshot:
	"""Everything this module can see about the network, and what it cannot."""
	sockets, socket_surfaces = collect_sockets()
	processes, process_surfaces = collect_processes()
	firewall_hash, policy, firewall_surfaces = collect_firewall()
	return Snapshot(
		sockets=sockets,
		processes=processes,
		surfaces=socket_surfaces + process_surfaces + firewall_surfaces,
		firewall_hash=firewall_hash,
		firewall_output_policy=policy,
	)
