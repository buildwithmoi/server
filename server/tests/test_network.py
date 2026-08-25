# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What this host listens on and talks to.

This detector covers the part of the incident that had consequences. The miner,
the SOCKS proxy and the x-ui panel were carrying other people's traffic, and
thirty-seven parties reported SSH brute-force leaving the address. None of it
needed an attacker login, so nothing built on authentication could see it.

A NOTE ON ADDRESSES IN THESE TESTS. Python's `ipaddress` treats the
documentation ranges — 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24 — as
PRIVATE, because they are not routable. So a test written with those addresses
silently exercises the internal path and passes without proving anything. It
happened once here already. Every external destination below is a real
routable address for that reason.

Frappe-free.
"""

from __future__ import annotations

import unittest

from server.security import network as N
from server.security import network_rules as R


def worst(findings):
	order = ["Critical", "High", "Medium", "Info"]
	return min((f.severity for f in findings), key=order.index) if findings else None


def sock(remote, port, process="", binary="", state="ESTAB"):
	return N.Socket("tcp", state, "10.0.0.5", 40000, remote, port, process, 999, binary, bool(binary))


class TestTheIncidentsTraffic(unittest.TestCase):
	def test_the_beacon_on_an_unexpected_port(self):
		findings = R.judge_outbound([sock("130.12.180.50", 4433, "kernel", "/usr/.local/kernel")])
		self.assertEqual(worst(findings), R.CRITICAL)

	def test_the_socks_proxy_carrying_traffic(self):
		sockets = [sock(f"45.61.187.{i}", 1080, "microsocks", "/usr/local/bin/microsocks") for i in range(3)]
		findings = R.judge_outbound(sockets)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertTrue(any("microsocks" in f.subject for f in findings))

	def test_outbound_ssh_brute_force(self):
		"""The exact reported abuse: SSH leaving this host to many destinations."""
		sockets = [sock(f"45.61.187.{i}", 22, "ssh", "/usr/bin/ssh") for i in range(8)]
		findings = R.judge_outbound(sockets)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertTrue(any("different hosts" in f.subject for f in findings))

	def test_the_miner_reaching_a_pool(self):
		findings = R.judge_outbound([sock("130.12.180.50", 3333, "xmrig", "/opt/xmrig/xmrig")])
		self.assertEqual(worst(findings), R.CRITICAL)

	def test_a_beacon_is_recognised_by_never_connecting(self):
		"""SYN-SENT that never becomes established. The incident's beacon sat in
		exactly this state, retrying forever, because its destination had
		already been blocked."""
		findings = R.judge_beacons({("130.12.180.50", 4433): R.BEACON_SCANS + 2})
		self.assertEqual(worst(findings), R.CRITICAL)

	def test_one_failed_connection_is_not_a_beacon(self):
		"""A slow DNS lookup would otherwise be an incident."""
		self.assertEqual(R.judge_beacons({("130.12.180.50", 4433): 1}), [])


class TestGitOverSSHIsNotAnIncident(unittest.TestCase):
	"""The specification asks for "outbound port 22 → Critical", and taken
	literally that is wrong here. `bench get-app` and `git pull` fetch private
	apps over SSH — this app's own core workflow — and the box had a live
	outbound port-22 connection within a minute of the collector being written.
	A rule that fires on that is one nobody keeps switched on.
	"""

	GIT = ("140.82.121.3",)

	def test_cloning_from_a_known_git_host_is_silent(self):
		findings = R.judge_outbound([sock("140.82.121.3", 22, "ssh", "/usr/bin/ssh")], git_host_addresses=self.GIT)
		self.assertEqual(findings, [])

	def test_ssh_anywhere_else_is_critical(self):
		findings = R.judge_outbound([sock("46.62.173.8", 22, "ssh", "/usr/bin/ssh")], git_host_addresses=self.GIT)
		self.assertEqual(worst(findings), R.CRITICAL)

	def test_many_destinations_is_critical_even_if_allowed(self):
		"""Fetching code reaches one or two hosts. Reaching many is the brute
		force, whoever the destinations claim to be."""
		allowed = tuple(f"140.82.121.{i}" for i in range(8))
		sockets = [sock(f"140.82.121.{i}", 22, "ssh", "/usr/bin/ssh") for i in range(8)]
		findings = R.judge_outbound(sockets, git_host_addresses=allowed)
		self.assertEqual(worst(findings), R.CRITICAL)


class TestOrdinaryTrafficIsSilent(unittest.TestCase):
	def test_the_ports_an_erpnext_host_actually_needs(self):
		for port, label in ((443, "HTTPS"), (80, "HTTP"), (53, "DNS"), (587, "SMTP"), (123, "NTP")):
			with self.subTest(port=port, label=label):
				self.assertEqual(R.judge_outbound([sock("8.8.8.8", port, "python")]), [])

	def test_internal_traffic_is_never_judged(self):
		for address in ("127.0.0.1", "10.0.0.9", "192.168.1.5", "172.16.0.1"):
			with self.subTest(address=address):
				self.assertEqual(R.judge_outbound([sock(address, 9999, "python")]), [])

	def test_the_documentation_ranges_count_as_internal(self):
		"""Guards the trap this file's docstring describes."""
		self.assertTrue(N.is_private("203.0.113.9"))
		self.assertFalse(N.is_private("130.12.180.50"))


class TestListeners(unittest.TestCase):
	def test_a_new_public_port_is_critical(self):
		listener = N.Socket("tcp", "LISTEN", "0.0.0.0", 4444, process="x", binary="/tmp/x")
		self.assertEqual(worst(R.judge_new_listener(listener)), R.CRITICAL)

	def test_a_new_loopback_port_is_high_not_critical(self):
		"""Bound to loopback it is reachable only from this host."""
		listener = N.Socket("tcp", "LISTEN", "127.0.0.1", 4444)
		self.assertEqual(worst(R.judge_new_listener(listener)), R.HIGH)

	def test_a_notorious_port_is_named(self):
		listener = N.Socket("tcp", "LISTEN", "127.0.0.1", 1080)
		findings = R.judge_new_listener(listener)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertIn("SOCKS", findings[0].detail)

	def test_a_port_closing_is_only_informational(self):
		listener = N.Socket("tcp", "LISTEN", "127.0.0.1", 8000)
		self.assertEqual(worst(R.judge_listener_gone(listener)), R.INFO)


class TestProcesses(unittest.TestCase):
	def test_a_deleted_binary_is_critical(self):
		process = N.Process(pid=1, binary="/usr/.local/kernel", deleted_binary=True)
		findings = R.judge_process(process)
		self.assertEqual(worst(findings), R.CRITICAL)
		self.assertIn("only copy left", findings[0].runbook)

	def test_running_from_a_temporary_directory_is_critical(self):
		for path in ("/tmp/x", "/var/tmp/x", "/dev/shm/x"):
			with self.subTest(path=path):
				self.assertEqual(worst(R.judge_process(N.Process(pid=1, binary=path))), R.CRITICAL)

	def test_known_mining_software_is_critical(self):
		process = N.Process(pid=1, binary="/opt/xmrig/xmrig", cmdline="xmrig --donate 0")
		self.assertEqual(worst(R.judge_process(process)), R.CRITICAL)

	def test_an_ordinary_bench_process_is_silent(self):
		process = N.Process(
			pid=1,
			binary="/home/patoo/fb-16-server/env/bin/python",
			cmdline="gunicorn frappe.app:application",
		)
		self.assertEqual(R.judge_process(process), [])


class TestParsing(unittest.TestCase):
	def test_ss_output_with_process_attribution(self):
		line = 'LISTEN 0 511 127.0.0.1:11006 0.0.0.0:* users:(("redis-server",pid=434,fd=6))'
		socket = N.parse_ss(line, "tcp")[0]
		self.assertEqual(socket.local_port, 11006)
		self.assertEqual(socket.process, "redis-server")
		self.assertEqual(socket.pid, 434)

	def test_ss_output_without_attribution(self):
		"""Sockets owned by another user come back with no process column, and
		must still be recorded — that is where an unexpected port would be."""
		socket = N.parse_ss("LISTEN 0 80 0.0.0.0:3306 0.0.0.0:*", "tcp")[0]
		self.assertEqual(socket.local_port, 3306)
		self.assertEqual(socket.pid, 0)
		self.assertTrue(socket.listening_publicly)

	def test_ipv6_addresses(self):
		socket = N.parse_ss("LISTEN 0 511 [::1]:8000 [::]:*", "tcp")[0]
		self.assertEqual(socket.local_address, "::1")
		self.assertEqual(socket.local_port, 8000)

	def test_a_socket_shared_by_many_workers_is_attributed_once(self):
		line = 'LISTEN 0 2048 127.0.0.1:8006 0.0.0.0:* users:(("gunicorn",pid=1341,fd=8),("gunicorn",pid=1340,fd=8))'
		sockets = N.parse_ss(line, "tcp")
		self.assertEqual(len(sockets), 1)
		self.assertEqual(sockets[0].pid, 1341)


class TestFirewall(unittest.TestCase):
	def test_a_changed_ruleset_is_reported(self):
		snapshot = N.Snapshot(firewall_hash="new", firewall_output_policy="drop")
		findings = R.judge_firewall("old", snapshot)
		self.assertEqual(worst(findings), R.HIGH)

	def test_an_unchanged_ruleset_is_silent(self):
		snapshot = N.Snapshot(firewall_hash="same", firewall_output_policy="drop")
		self.assertEqual(R.judge_firewall("same", snapshot), [])

	def test_a_missing_egress_lock_is_reported_when_expected(self):
		snapshot = N.Snapshot(firewall_hash="h", firewall_output_policy="accept")
		findings = R.judge_firewall("h", snapshot, expect_output_drop=True)
		self.assertTrue(any("no longer being filtered" in f.subject for f in findings))

	def test_nothing_is_claimed_when_the_firewall_cannot_be_read(self):
		"""An empty hash means no visibility, not an empty ruleset."""
		self.assertEqual(R.judge_firewall("", N.Snapshot(), expect_output_drop=True), [])


class TestCoverage(unittest.TestCase):
	def test_an_unreadable_firewall_names_what_it_costs(self):
		surfaces = [N.Surface("firewall", "nft", False, "not readable without root")]
		findings = R.judge_coverage(surfaces)
		self.assertIn("would not be noticed", findings[0].detail)

	def test_everything_readable_is_silent(self):
		self.assertEqual(R.judge_coverage([N.Surface("sockets", "listening", True)]), [])


class TestAgainstThisHost(unittest.TestCase):
	def test_the_collector_sees_sockets_and_processes(self):
		snapshot = N.collect()
		self.assertTrue(snapshot.sockets)
		self.assertTrue(snapshot.processes)

	def test_ordinary_processes_on_this_host_produce_nothing(self):
		"""A detector that flags this machine's own daemons is one nobody
		reads."""
		snapshot = N.collect()
		noisy = [
			(p.pid, p.binary, [f.subject for f in R.judge_process(p)])
			for p in snapshot.processes
			if R.judge_process(p)
		]
		self.assertEqual(noisy, [], f"ordinary processes produced findings: {noisy[:3]}")


if __name__ == "__main__":
	unittest.main()
