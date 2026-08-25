# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The filesystem detector, tested against a box that is not compromised.

No site, no database, no root, and — the point — no compromised host to
borrow. The collector is exercised against real directories where that is
safe, and every judgement is exercised against hand-built items, because the
findings that matter are the ones this machine will hopefully never produce.

The last class is the one worth reading: it replays the artefacts a real
intrusion leaves on disk and asserts each is caught, at the severity that
would actually get someone out of bed.
"""

import os
import stat
import tempfile
import unittest

from server.security import filesystem as fs
from server.security import filesystem_rules as fr


def _item(kind, path, **detail):
	package = detail.pop("package", "")
	content_hash = detail.pop("content_hash", "")
	return fs.Item(
		kind=kind, identifier=path, path=path, package=package, content_hash=content_hash, detail=detail
	)


class TestDpkgVerifyParsing(unittest.TestCase):
	"""The format is pinned with --verify-format rpm; this is why.

	dpkg's own man page says the default output format "might change in the
	future". Parsing it correctly is the difference between noticing a
	replaced binary and reporting a clean system.
	"""

	SAMPLE = """\
missing     /usr/lib/python3/dist-packages/pkg_resources/__init__.py
??5?????? c /etc/nginx/nginx.conf
??5??????   /usr/bin/sshd
?????????  c /etc/sudoers
"""

	def test_separates_the_four_shapes(self):
		records = fs.parse_dpkg_verify(self.SAMPLE)
		self.assertEqual(len(records), 4)
		by_path = {r.path: r for r in records}
		self.assertTrue(by_path["/usr/lib/python3/dist-packages/pkg_resources/__init__.py"].missing)
		self.assertTrue(by_path["/etc/nginx/nginx.conf"].is_conffile)
		self.assertFalse(by_path["/usr/bin/sshd"].is_conffile)

	def test_checksum_flag_is_position_three(self):
		records = {r.path: r for r in fs.parse_dpkg_verify(self.SAMPLE)}
		self.assertTrue(records["/usr/bin/sshd"].checksum_differs)
		self.assertTrue(records["/etc/nginx/nginx.conf"].checksum_differs)
		self.assertFalse(records["/etc/sudoers"].checksum_differs)

	def test_missing_lines_are_not_checksum_failures(self):
		"""337 of this box's 341 verify lines are "missing".

		They are pip having tidied up after itself. Reading one as a modified
		file would bury the two that matter under three hundred that do not.
		"""
		record = fs.parse_dpkg_verify("missing     /usr/share/doc/thing/README")[0]
		self.assertTrue(record.missing)
		self.assertFalse(record.checksum_differs)

	def test_garbage_is_ignored_not_guessed_at(self):
		self.assertEqual(fs.parse_dpkg_verify("dpkg: warning: something\n\n"), [])


class TestConffileDistinction(unittest.TestCase):
	"""The single distinction the package check lives or dies on."""

	def test_edited_config_is_not_an_alert(self):
		findings = fr.judge_package_integrity(
			[_item(fs.KIND_PACKAGE, "/etc/nginx/nginx.conf", conffile=True)]
		)
		self.assertTrue(all(f.severity == fr.INFO for f in findings))

	def test_modified_binary_is_critical(self):
		findings = fr.judge_package_integrity([_item(fs.KIND_PACKAGE, "/usr/sbin/sshd", conffile=False)])
		self.assertEqual([f.severity for f in findings], [fr.CRITICAL])

	def test_config_noise_never_hides_a_binary(self):
		"""A real box has edited conffiles all the time.

		The Critical has to survive being outnumbered by them, because that is
		the normal state of every configured server.
		"""
		items = [_item(fs.KIND_PACKAGE, f"/etc/thing{n}.conf", conffile=True) for n in range(20)]
		items.append(_item(fs.KIND_PACKAGE, "/usr/bin/sudo", conffile=False))
		criticals = [f for f in fr.judge_package_integrity(items) if f.severity == fr.CRITICAL]
		self.assertEqual(len(criticals), 1)
		self.assertIn("/usr/bin/sudo", criticals[0].subject)


class TestSetuidRules(unittest.TestCase):
	def test_new_unowned_setuid_is_critical(self):
		item = _item(fs.KIND_SETUID, "/usr/bin/.hidden", setuid=True, owner="root:root")
		findings = fr.judge_setuid(fr.APPEARED, item)
		self.assertEqual([f.severity for f in findings], [fr.CRITICAL])

	def test_new_package_owned_setuid_is_not_critical(self):
		"""An upgrade adding one is legitimate and must not wake anyone.

		Recorded, because the list of things that can escalate privilege
		should not grow unnoticed — but not Critical, because a package
		upgrade is the overwhelmingly likely cause.
		"""
		item = _item(fs.KIND_SETUID, "/usr/bin/newthing", setuid=True, owner="root:root", package="util-linux")
		self.assertEqual([f.severity for f in fr.judge_setuid(fr.APPEARED, item)], [fr.MEDIUM])

	def test_modified_setuid_binary_is_critical_even_when_packaged(self):
		"""Especially when packaged. Replacing /usr/bin/sudo is the point."""
		item = _item(fs.KIND_SETUID, "/usr/bin/sudo", setuid=True, owner="root:root", package="sudo", content_hash="b" * 64)
		findings = fr.judge_setuid(fr.MODIFIED, item, previous_hash="a" * 64)
		self.assertEqual([f.severity for f in findings], [fr.CRITICAL])

	def test_setuid_owned_by_non_root_is_critical(self):
		item = _item(fs.KIND_SETUID, "/usr/bin/tool", setuid=True, owner="patoo:patoo", package="thing")
		severities = [f.severity for f in fr.shape_findings(item)]
		self.assertIn(fr.CRITICAL, severities)

	def test_setgid_owned_by_a_group_is_not_treated_as_setuid_root(self):
		"""Stock Ubuntu ships nine of these; crontab and ssh-agent are two.

		Reading a setgid binary's group owner as though it were a setuid
		owner would turn the whole stock baseline Critical, which is the
		failure mode this whole module is written to avoid.
		"""
		item = _item(
			fs.KIND_SETUID, "/usr/bin/crontab", setgid=True, setuid=False, owner="root:crontab", package="cron"
		)
		self.assertEqual([f.severity for f in fr.shape_findings(item)], [])

	def test_the_real_stock_baseline_raises_nothing(self):
		"""The strongest available check short of a compromised host.

		Sweeps this machine's actual setuid binaries and asserts none of them
		is a finding. If a rule is written too broadly, twenty-one stock files
		say so immediately.
		"""
		items, _ = fs.collect_setuid()
		if not items:
			self.skipTest("no setuid binaries visible")
		noisy = [(i.path, f.severity, f.subject) for i in items for f in fr.shape_findings(i)]
		self.assertEqual(noisy, [], f"stock binaries raised findings: {noisy}")


class TestTempAndWritableRules(unittest.TestCase):
	def test_setuid_binary_in_temp_is_critical(self):
		item = _item(fs.KIND_TEMP_BINARY, "/tmp/.x", setuid=True, owner="root:root")
		self.assertEqual([f.severity for f in fr.judge_temp_binary(item)], [fr.CRITICAL])

	def test_ordinary_binary_in_temp_is_high_not_critical(self):
		"""Build systems put compiled output in /tmp constantly.

		This box has two such files right now. High gets them looked at;
		Critical would train the reader to dismiss the category.
		"""
		item = _item(fs.KIND_TEMP_BINARY, "/tmp/build/out", setuid=False, owner="patoo:patoo")
		self.assertEqual([f.severity for f in fr.judge_temp_binary(item)], [fr.HIGH])

	def test_world_writable_executable_is_critical(self):
		item = _item(fs.KIND_WORLD_WRITABLE, "/usr/local/bin/deploy", executable=True, mode="-rwxrwxrwx")
		self.assertEqual([f.severity for f in fr.judge_world_writable(item)], [fr.CRITICAL])

	def test_runbook_names_the_actual_command(self):
		"""Every finding carries what to do; a chmod finding should say chmod.

		The spec requires a runbook on every alert. A runbook that restates
		the problem is not one.
		"""
		item = _item(fs.KIND_WORLD_WRITABLE, "/etc/thing.conf", executable=False, mode="-rw-rw-rw-")
		self.assertIn("chmod o-w /etc/thing.conf", fr.judge_world_writable(item)[0].runbook)


class TestCollectorMechanics(unittest.TestCase):
	def test_merged_usr_is_not_swept_twice(self):
		"""/bin is a symlink to usr/bin on Ubuntu 24.04.

		The first version of this module reported 37 setuid binaries where
		find(1) reports 21 — the same files under two spellings. Each phantom
		would have needed its own baseline and alerted on its own forever.
		"""
		pairs = fs._distinct_roots(("/usr", "/bin", "/sbin"))
		kept = [resolved for _, resolved in pairs if resolved]
		self.assertEqual(kept, ["/usr"])

	def test_every_requested_root_still_gets_a_surface(self):
		"""Deduplicating must not silently drop coverage.

		"Did you look in /sbin" deserves an answer, and "it is the same place
		as /usr/sbin" is one. Dropping the row would read as never having asked.
		"""
		pairs = fs._distinct_roots(("/usr", "/bin", "/sbin"))
		self.assertEqual([requested for requested, _ in pairs], ["/usr", "/bin", "/sbin"])

	def test_elf_detection_reads_magic_not_the_extension(self):
		with tempfile.TemporaryDirectory() as tmp:
			elf = os.path.join(tmp, "no-extension")
			with open(elf, "wb") as handle:
				handle.write(b"\x7fELF\x02\x01\x01\x00rest")
			script = os.path.join(tmp, "thing.sh")
			with open(script, "w") as handle:
				handle.write("#!/bin/sh\necho hi\n")
			self.assertTrue(fs._is_elf(elf))
			self.assertFalse(fs._is_elf(script))

	def test_a_shell_script_in_temp_is_not_a_finding(self):
		"""734 executable files in /tmp here; 2 are ELF.

		Without this filter the rule is unusable, so the filter is tested
		rather than trusted.
		"""
		with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
			script = os.path.join(tmp, "build.sh")
			with open(script, "w") as handle:
				handle.write("#!/bin/sh\n")
			os.chmod(script, 0o755)
			items, _ = fs.collect_temp_binaries((tmp,))
			self.assertEqual(items, [])

	def test_an_elf_in_temp_is_found(self):
		with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
			binary = os.path.join(tmp, "payload")
			with open(binary, "wb") as handle:
				handle.write(b"\x7fELF" + b"\x00" * 64)
			os.chmod(binary, 0o755)
			items, surfaces = fs.collect_temp_binaries((tmp,))
			self.assertEqual([i.path for i in items], [binary])
			self.assertTrue(all(s.readable for s in surfaces))

	def test_unreadable_surface_is_reported_not_swallowed(self):
		"""The confident empty answer is the dangerous one."""
		items, surfaces = fs.collect_temp_binaries(("/definitely/not/here",))
		self.assertEqual(items, [])
		self.assertEqual(len(surfaces), 1)

	def test_walk_does_not_follow_symlinks(self):
		"""A symlink into /proc turns a sweep into an eternity."""
		with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
			os.symlink("/proc", os.path.join(tmp, "loop"))
			paths = [p for p, _ in fs._walk(tmp)]
			self.assertEqual(paths, [])


class TestIncidentReplay(unittest.TestCase):
	"""The artefacts a real intrusion leaves on disk, each asserted caught.

	Built from the incident this app exists because of: a foothold that became
	root, stayed for eight months, and was found by the hosting provider
	rather than by anyone looking at the machine. These are the disk-side
	traces that would have been visible the whole time.
	"""

	def _severities(self, findings):
		return {f.severity for f in findings}

	def test_backdoored_shell_dropped_as_setuid(self):
		"""The oldest trick there is: a copy of /bin/bash, setuid root."""
		item = _item(fs.KIND_SETUID, "/usr/bin/.sysd", setuid=True, owner="root:root")
		self.assertIn(fr.CRITICAL, self._severities(fr.judge_setuid(fr.APPEARED, item)))

	def test_sudo_replaced_to_capture_passwords(self):
		item = _item(
			fs.KIND_SETUID, "/usr/bin/sudo", setuid=True, owner="root:root", package="sudo", content_hash="f" * 64
		)
		findings = fr.judge_setuid(fr.MODIFIED, item, previous_hash="a" * 64)
		self.assertIn(fr.CRITICAL, self._severities(findings))

	def test_sshd_replaced_on_disk(self):
		findings = fr.judge_package_integrity([_item(fs.KIND_PACKAGE, "/usr/sbin/sshd", conffile=False)])
		self.assertIn(fr.CRITICAL, self._severities(findings))

	def test_miner_staged_in_dev_shm(self):
		"""/dev/shm is memory-backed, so it leaves nothing on the disk.

		Which is exactly why it gets used, and why it is swept.
		"""
		item = _item(fs.KIND_TEMP_BINARY, "/dev/shm/kdevtmpfsi", setuid=False, owner="root:root")
		self.assertIn(fr.HIGH, self._severities(fr.judge_temp_binary(item)))

	def test_world_writable_cron_script(self):
		"""Root runs it; anyone can rewrite it. No exploit required."""
		item = _item(fs.KIND_WORLD_WRITABLE, "/etc/cron.daily/backup", executable=True, mode="-rwxrwxrwx")
		self.assertIn(fr.CRITICAL, self._severities(fr.judge_world_writable(item)))

	def test_setuid_binary_planted_in_a_vendor_directory(self):
		item = _item(fs.KIND_SETUID, "/opt/vendor/bin/helper", setuid=True, owner="root:root")
		self.assertIn(fr.HIGH, self._severities(fr.shape_findings(item)))

	def test_every_artefact_carries_a_runbook(self):
		"""The spec requires one on every alert, and means it.

		An alert that says something is wrong and not what to do about it
		gets acknowledged rather than acted on.
		"""
		findings = (
			fr.judge_setuid(fr.APPEARED, _item(fs.KIND_SETUID, "/usr/bin/.x", setuid=True, owner="root:root"))
			+ fr.judge_package_integrity([_item(fs.KIND_PACKAGE, "/usr/sbin/sshd", conffile=False)])
			+ fr.judge_temp_binary(_item(fs.KIND_TEMP_BINARY, "/dev/shm/x", owner="root:root"))
			+ fr.judge_world_writable(_item(fs.KIND_WORLD_WRITABLE, "/etc/x", executable=True))
			+ fr.judge_coverage([fs.Surface(fs.KIND_SETUID, "/usr", False, "denied", 0)])
		)
		self.assertTrue(findings)
		for finding in findings:
			with self.subTest(subject=finding.subject):
				self.assertTrue(finding.runbook.strip())
				self.assertNotEqual(finding.runbook.strip(), finding.detail.strip())
