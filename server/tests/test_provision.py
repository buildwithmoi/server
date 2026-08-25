# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Building a bench: the arithmetic and the refusals, with nothing spent.

The thing under test takes several minutes and four gigabytes to try for real,
which is exactly why the parts that can be decided beforehand are separated
out. Everything here runs with no site, no database and no subprocess except
the one that asks uv where a Python is.

Port allocation is tested against synthetic input rather than this machine's
benches, deliberately. An earlier version of this plan asserted "index 5 is
free here" — it was not: a `fb-15-2` existed at 8005 that a `fb-16-*` glob had
not matched. A test that reads live state asserts today's accident.
"""

import os
import tempfile
import unittest

from server.bench import provision


class TestPortArithmetic(unittest.TestCase):
	"""One index drives four ports, which is what every bench here does."""

	def test_an_index_expands_to_the_whole_block(self):
		ports = provision.ports_for(5)
		self.assertEqual(
			(ports.webserver, ports.socketio, ports.redis_queue, ports.redis_cache),
			(8005, 9005, 11005, 13005),
		)

	def test_an_index_is_recovered_from_a_web_port(self):
		self.assertEqual(provision.index_of(8007), 7)

	def test_a_port_outside_the_scheme_yields_no_index(self):
		"""A bench somebody configured by hand on 3000 is not in a block.

		Returning 0 or a negative would let it collide with a real allocation.
		"""
		for port in (3000, 0, None, 9999):
			self.assertIsNone(provision.index_of(port), port)

	def test_the_lowest_free_index_wins_not_the_next_after_the_highest(self):
		"""Benches get removed, and counting upward leaves the hole forever.

		It also marches the numbers up every time somebody rebuilds one.
		"""
		self.assertEqual(provision.allocate_index([8001, 8002, 8004]), 3)

	def test_a_bench_on_the_base_port_does_not_consume_a_block(self):
		"""8000 is bench init's default and maps to index 0.

		Allocation starts at 1, so a bench sitting on the defaults neither
		takes a block nor gets handed one.
		"""
		self.assertEqual(provision.allocate_index([8000]), 1)

	def test_allocation_starts_at_one_on_an_empty_machine(self):
		self.assertEqual(provision.allocate_index([]), 1)

	def test_running_out_of_blocks_is_refused_with_a_reason(self):
		full = [8000 + n for n in range(1, provision.MAX_INDEX + 1)]
		with self.assertRaises(provision.Refusal) as caught:
			provision.allocate_index(full)
		self.assertIn("Remove a bench", str(caught.exception))


class TestInterpreterResolution(unittest.TestCase):
	"""`bench init --python` takes a PATH, and the one v16 needs is not on PATH.

	Passing the bare name gives "no such file or directory" a minute into a
	clone, with nothing saying which python it meant.
	"""

	def test_version_16_resolves_to_a_real_executable(self):
		try:
			path = provision.resolve_interpreter("16")
		except provision.Refusal as exc:
			self.skipTest(f"no 3.14 available here: {exc}")
		self.assertTrue(os.path.isabs(path), "bench needs a path, not a name")
		self.assertTrue(os.access(path, os.X_OK))

	def test_version_15_resolves_too(self):
		try:
			path = provision.resolve_interpreter("15")
		except provision.Refusal as exc:
			self.skipTest(f"no 3.12 available here: {exc}")
		self.assertTrue(os.access(path, os.X_OK))

	def test_an_unknown_version_names_the_ones_that_work(self):
		with self.assertRaises(provision.Refusal) as caught:
			provision.resolve_interpreter("14")
		self.assertIn("16", str(caught.exception))

	def test_a_missing_uv_says_how_to_fix_it(self):
		with self.assertRaises(provision.Refusal) as caught:
			provision.resolve_interpreter("16", uv="definitely-not-installed")
		self.assertIn("uv", str(caught.exception).lower())

	def test_an_uninstalled_python_names_the_install_command(self):
		"""The actionable half. "Python 3.14 not found" leaves somebody
		guessing; naming `uv python install 3.14` does not."""
		import subprocess
		from unittest.mock import patch

		fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
		with patch("shutil.which", return_value="/usr/local/bin/uv"), patch(
			"subprocess.run", return_value=fake
		):
			with self.assertRaises(provision.Refusal) as caught:
				provision.resolve_interpreter("16")
		self.assertIn("uv python install", str(caught.exception))


class TestNameValidation(unittest.TestCase):
	def test_a_bench_name_becomes_a_directory(self):
		self.assertEqual(provision.validate_names("Fb-16-New", "")[0], "fb-16-new")

	def test_a_name_with_a_space_is_refused(self):
		with self.assertRaises(provision.Refusal):
			provision.validate_names("my bench", "")

	def test_a_name_that_would_escape_the_root_is_refused(self):
		"""It becomes a path segment under the bench root."""
		for attempt in ("../evil", "/etc", "a/b"):
			with self.assertRaises(provision.Refusal):
				provision.validate_names(attempt, "")

	def test_a_site_name_has_to_be_a_hostname(self):
		"""It becomes a directory AND an nginx server_name."""
		with self.assertRaises(provision.Refusal):
			provision.validate_names("ok", "not a hostname!")

	def test_no_site_is_allowed(self):
		"""A bench with no site on it is a legitimate thing to build."""
		self.assertEqual(provision.validate_names("ok", "")[1], "")


class TestTheCommands(unittest.TestCase):
	BENCH = "/usr/local/bin/bench"

	def test_init_passes_the_interpreter_path_and_the_branch(self):
		argv = provision.build_init_argv(self.BENCH, "fb-16-new", "/opt/py/3.14", "16")
		self.assertIn("--python", argv)
		self.assertEqual(argv[argv.index("--python") + 1], "/opt/py/3.14")
		self.assertEqual(argv[argv.index("--frappe-branch") + 1], "version-16")

	def test_assets_are_skipped_by_default(self):
		"""The largest memory consumer in the whole process, on a box with
		about 2.6 GB free. A bench that dies at the last step has still spent
		four gigabytes and several minutes."""
		self.assertIn("--skip-assets", provision.build_init_argv(self.BENCH, "b", "/py", "16"))
		self.assertNotIn(
			"--skip-assets", provision.build_init_argv(self.BENCH, "b", "/py", "16", skip_assets=False)
		)

	def test_the_port_command_moves_all_four_and_points_socketio_at_the_cache(self):
		"""Sharing the cache port looks like a mistake and is not — it is what
		bench's own generated config does, and every bench here follows it."""
		argv = provision.build_port_argv(self.BENCH, provision.ports_for(5))
		joined = " ".join(argv)
		self.assertIn("webserver_port 8005", joined)
		self.assertIn("11005", joined)
		self.assertIn("13005", joined)

	def test_string_values_are_sent_as_python_literals(self):
		"""`bench config set-common-config` runs ast.literal_eval on the value.

		A bare `redis://127.0.0.1:11005` is parsed as Python source and dies
		with "SyntaxError: invalid syntax" pointing at the `//`. Caught on a
		real run, after `bench init` had already spent four gigabytes. The
		numbers work unquoted because `8005` is already a valid literal, which
		is exactly why it is easy to miss — half the arguments are fine.
		"""
		import ast

		argv = provision.build_port_argv(self.BENCH, provision.ports_for(5))
		values = [argv[i + 1] for i, token in enumerate(argv) if token == "-c"]
		values = [argv[argv.index(name) + 1] for name in values]

		for value in values:
			with self.subTest(value=value):
				# The check bench itself performs. Anything that raises here
				# would have failed the command.
				ast.literal_eval(value)

	def test_the_redis_urls_survive_literal_eval_as_urls(self):
		import ast

		argv = provision.build_port_argv(self.BENCH, provision.ports_for(5))
		queue = argv[argv.index("redis_queue") + 1]
		self.assertEqual(ast.literal_eval(queue), "redis://127.0.0.1:11005")

	def test_redis_and_procfile_are_regenerated(self):
		"""Ports live in three places. Setting only common_site_config is the
		classic half-fix: the config says 13005 and redis is still on 13000,
		sharing another bench's cache."""
		self.assertEqual(provision.build_redis_argv(self.BENCH)[1:], ["setup", "redis"])
		self.assertEqual(provision.build_procfile_argv(self.BENCH)[1:], ["setup", "procfile"])

	def test_new_site_refuses_without_the_root_password(self):
		with self.assertRaises(provision.Refusal):
			provision.build_new_site_argv(self.BENCH, "a.test", "")

	def test_the_first_site_becomes_the_default(self):
		"""So `bench <command>` works without --site afterwards, including for
		the operator running things by hand later."""
		self.assertIn("--set-default", provision.build_new_site_argv(self.BENCH, "a.test", "pw"))

	def test_force_is_never_passed(self):
		"""It drops an existing database of the same name without asking.

		This app does not delete a database as a side effect of creating one —
		if the name is taken, new-site should fail and say so.
		"""
		argv = provision.build_new_site_argv(self.BENCH, "a.test", "pw", admin_password="x")
		self.assertNotIn("--force", argv)

	def test_both_passwords_are_hidden_by_the_existing_redaction(self):
		"""`restore.SECRET_FLAGS` already covers both flags, so the command
		stored on the row and shown in the log needs no new handling."""
		from server.bench import restore

		argv = provision.build_new_site_argv(self.BENCH, "a.test", "ROOTPW", admin_password="ADMINPW")
		shown = " ".join(restore.redact(argv))
		self.assertNotIn("ROOTPW", shown)
		self.assertNotIn("ADMINPW", shown)
		self.assertIn("a.test", shown, "the site name is not a secret and must stay readable")


class TestPreflight(unittest.TestCase):
	def _checks(self, **kwargs):
		defaults = {
			"bench_root": tempfile.gettempdir(),
			"bench_name": "fb-test-new",
			"site_name": "a.test",
			"db_root_password": "pw",
		}
		defaults.update(kwargs)
		return {check.key: check for check in provision.preflight(**defaults)}

	def test_an_existing_directory_is_blocking(self):
		with tempfile.TemporaryDirectory() as tmp:
			os.mkdir(os.path.join(tmp, "taken"))
			checks = self._checks(bench_root=tmp, bench_name="taken")
		self.assertFalse(checks["target"].ok)
		self.assertTrue(checks["target"].blocking)

	def test_a_free_directory_passes(self):
		with tempfile.TemporaryDirectory() as tmp:
			checks = self._checks(bench_root=tmp, bench_name="free")
		self.assertTrue(checks["target"].ok)

	def test_a_missing_password_blocks_when_a_site_was_asked_for(self):
		checks = self._checks(db_root_password="")
		self.assertFalse(checks["password"].ok)

	def test_a_missing_password_is_fine_with_no_site(self):
		"""A bench with no site needs no database credential at all."""
		checks = self._checks(site_name="", db_root_password="")
		self.assertTrue(checks["password"].ok)

	def test_memory_is_advisory_rather_than_blocking(self):
		"""A tight box can still build a bench, slowly. It is a reason this
		might not finish, not proof that it cannot."""
		self.assertFalse(self._checks()["memory"].blocking)

	def test_a_bad_name_short_circuits_to_one_finding(self):
		"""Rather than reporting five failures that are all the same problem."""
		checks = provision.preflight(
			bench_root="/tmp", bench_name="bad name", site_name="", db_root_password=""
		)
		self.assertEqual(len(checks), 1)
		self.assertEqual(checks[0].key, "names")

	def test_every_failing_check_says_something_actionable(self):
		with tempfile.TemporaryDirectory() as tmp:
			os.mkdir(os.path.join(tmp, "taken"))
			checks = provision.preflight(
				bench_root=tmp, bench_name="taken", site_name="a.test", db_root_password=""
			)
		for check in checks:
			if not check.ok:
				with self.subTest(check=check.key):
					self.assertGreater(len(check.detail), 20)


class TestTheStepPlan(unittest.TestCase):
	def test_every_app_gets_its_own_fetch_and_install_step(self):
		""""Failed while cloning erpnext" is a different problem from "failed
		while cloning the private one nobody has access to"."""
		from server.bench import steps

		keys = [s.key for s in steps.for_provision(["erpnext", "hrms"], True, False)]
		self.assertIn("get:erpnext", keys)
		self.assertIn("get:hrms", keys)
		self.assertIn("install:erpnext", keys)
		self.assertIn("install:hrms", keys)

	def test_no_site_means_no_site_or_install_steps(self):
		from server.bench import steps

		keys = [s.key for s in steps.for_provision(["erpnext"], False, False)]
		self.assertNotIn("site", keys)
		self.assertNotIn("install:erpnext", keys)
		self.assertIn("get:erpnext", keys)

	def test_the_ports_step_is_always_there(self):
		"""It is what stops the new bench sharing redis with an existing one."""
		from server.bench import steps

		self.assertIn("ports", [s.key for s in steps.for_provision([], False, False)])

	def test_fetching_happens_before_the_site_is_created(self):
		"""A failed clone should not leave a database behind."""
		from server.bench import steps

		keys = [s.key for s in steps.for_provision(["erpnext"], True, False)]
		self.assertLess(keys.index("get:erpnext"), keys.index("site"))


class TestExplainingAFailedInit(unittest.TestCase):
	"""Both halves came from the first real run, which failed.

	The cause was `fatal: fetch-pack: invalid index-pack output` — a hundred
	lines above the traceback bench prints — and the error summary said only
	"bench init exited 1". The retry then failed for a completely different-
	looking reason, because the partial directory was still there.
	"""

	def _explain(self, output, code=1):
		import types

		from server.bench import installer

		request = types.SimpleNamespace(
			output=output, provision_bench_name="fb-16-new", allow_merge=False
		)
		return installer._explain_failure(code, False, 3600, request, "bench init")

	def test_the_git_memory_failure_is_named(self):
		"""It is the most common way bench init fails on a healthy machine,
		and it does not look like a memory problem in the log."""
		message = self._explain("...\nfatal: fetch-pack: invalid index-pack output\n...")
		self.assertIn("memory", message)

	def test_a_dns_failure_is_named(self):
		self.assertIn("reach github.com", self._explain("fatal: Could not resolve host: github.com"))

	def test_a_full_disk_is_named(self):
		self.assertIn("disk filled", self._explain("fatal: No space left on device"))

	def test_the_leftover_directory_is_always_mentioned(self):
		"""bench asks "roll back? [y/N]" and a job cannot answer, so it aborts
		and leaves the directory. The next attempt then fails the pre-flight
		with "already exists", which reads as an unrelated problem.
		"""
		for output in ("fatal: fetch-pack: invalid index-pack output", "something unrecognised"):
			with self.subTest(output=output[:20]):
				message = self._explain(output)
				self.assertIn("rm -rf", message)
				self.assertIn("fb-16-new", message)

	def test_an_unrecognised_failure_says_where_to_look(self):
		"""Rather than repeating the exit code and stopping."""
		message = self._explain("some output nobody anticipated")
		self.assertIn("log above", message)

	def test_a_timeout_still_wins_over_the_init_explanation(self):
		"""Order matters. A watchdog kill reported as a clone problem sends
		somebody looking at their network instead of the timeout setting."""
		import types

		from server.bench import installer

		request = types.SimpleNamespace(output="", provision_bench_name="x", allow_merge=False)
		message = installer._explain_failure(-9, True, 3600, request, "bench init")
		self.assertIn("terminated", message)


class TestABuiltBenchIsNotJudgedByTheExitCode(unittest.TestCase):
	"""`bench init` exits non-zero on a machine with no passwordless sudo.

	It clones frappe, builds the virtualenv, installs every dependency, writes
	the config — and then runs `sudo supervisorctl status`, which fails and
	takes the whole command's exit code with it. Observed here: a bench with
	Python 3.14.6 and frappe 16.31.0 importable, reported as a failure after
	four gigabytes and several minutes.

	The same shape as the `get-app` quirk this app already handles with
	`_clone_landed`. The exit code answers "did the command end cleanly",
	which is a different question from "is there a bench here".
	"""

	def _bench(self, tmp, markers=("apps", "sites", "config", "logs", "env"), python=True, frappe=True):
		root = os.path.join(tmp, "b")
		for marker in markers:
			os.makedirs(os.path.join(root, marker), exist_ok=True)
		if python:
			binary = os.path.join(root, "env", "bin")
			os.makedirs(binary, exist_ok=True)
			path = os.path.join(binary, "python")
			with open(path, "w") as handle:
				handle.write("#!/bin/sh\n")
			os.chmod(path, 0o755)
		if frappe:
			os.makedirs(os.path.join(root, "apps", "frappe"), exist_ok=True)
		return root

	def test_a_complete_bench_is_recognised(self):
		with tempfile.TemporaryDirectory() as tmp:
			self.assertTrue(provision.bench_landed(self._bench(tmp)))

	def test_a_directory_with_no_virtualenv_is_not_a_bench(self):
		"""The line between "got far enough to matter" and "made some
		directories before it died"."""
		with tempfile.TemporaryDirectory() as tmp:
			self.assertFalse(provision.bench_landed(self._bench(tmp, python=False)))

	def test_a_bench_without_frappe_is_not_a_bench(self):
		with tempfile.TemporaryDirectory() as tmp:
			self.assertFalse(provision.bench_landed(self._bench(tmp, frappe=False)))

	def test_a_missing_marker_directory_fails_the_check(self):
		with tempfile.TemporaryDirectory() as tmp:
			self.assertFalse(
				provision.bench_landed(self._bench(tmp, markers=("apps", "sites", "config")))
			)

	def test_an_unrelated_directory_is_not_a_bench(self):
		self.assertFalse(provision.bench_landed(tempfile.gettempdir()))

	def test_a_path_that_does_not_exist_is_not_a_bench(self):
		self.assertFalse(provision.bench_landed("/definitely/not/here"))
