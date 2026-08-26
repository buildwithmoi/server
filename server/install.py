# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Install-time setup and environment verification.

WHY THIS EXISTS. This app has no third-party Python dependencies — everything is
the standard library plus frappe — so `bench get-app` cannot fail for a missing
package. What it CAN do is install cleanly onto a machine that quietly cannot do
the job: no readable authentication log, no git, no bench on PATH. Those are
operating-system facts, not pip requirements, so the only honest thing is to
check them at install time and say so.

Nothing here aborts the installation. A server with no journald is perfectly
usable through the auth.log reader, and a server that will only ever manage
benches does not need either. Refusing to install would be wrong; installing
silently and behaving as if all is well would be worse.
"""

import os
import shutil
import subprocess

import frappe

#: Commands the app shells out to, and what stops working without each.
REQUIRED_COMMANDS = {
	"git": "cloning and pulling apps",
	"journalctl": "reading SSH events from the systemd journal (auth.log is the fallback)",
	"ssh": "authenticating to GitHub for private repositories",
}

#: Needed only by the features that use them, so a server without these is
#: reported as limited rather than broken. Making certbot a hard requirement
#: would flag every bench that serves over plain HTTP behind something else.
OPTIONAL_COMMANDS = {
	"certbot": (
		"issuing and renewing Let's Encrypt certificates from Benches → Set SSL. "
		"Install with: sudo apt install certbot python3-certbot-nginx"
	),
}


def check_prerequisites() -> dict:
	"""Report what this machine can and cannot do. Never raises."""
	from server.server.doctype.server_settings.server_settings import get_settings

	commands = {}
	for name, purpose in REQUIRED_COMMANDS.items():
		path = shutil.which(name)
		commands[name] = {"found": bool(path), "path": path, "purpose": purpose}

	settings = get_settings()
	bench_exe = (settings.bench_executable or "").strip()
	commands["bench"] = {
		"found": bool(bench_exe) and os.path.isfile(bench_exe) and os.access(bench_exe, os.X_OK),
		"path": bench_exe,
		"purpose": "installing apps into benches",
	}

	optional = {}
	for name, purpose in OPTIONAL_COMMANDS.items():
		path = shutil.which(name)
		optional[name] = {"found": bool(path), "path": path, "purpose": purpose}

	auth_log = (settings.auth_log_path or "").strip()
	logs = {
		"auth_log_path": auth_log,
		"auth_log_readable": bool(auth_log and os.access(auth_log, os.R_OK)),
		"journal_readable": _journal_readable(),
	}

	problems = []
	for name, info in commands.items():
		if not info["found"]:
			problems.append(f"{name} not found — {info['purpose']} will not work.")
	if not logs["journal_readable"] and not logs["auth_log_readable"]:
		problems.append(
			"Neither the systemd journal nor the auth log is readable, so no SSH events can be "
			"collected. On Debian and Ubuntu the fix is to put the bench user in the 'adm' group: "
			"sudo usermod -aG adm $USER (then log out and back in)."
		)

	# Advisory, never a problem: these limit what the app can do, they do not
	# stop it working.
	notes = [
		f"{name} not found — {info['purpose']}"
		for name, info in optional.items()
		if not info["found"]
	]

	return {
		"commands": commands,
		"optional": optional,
		"logs": logs,
		"problems": problems,
		"notes": notes,
		"ok": not problems,
	}


def _journal_readable() -> bool:
	"""Can we see OTHER users' journal entries, not just our own?

	`journalctl` succeeding proves nothing: without the right group it runs
	happily and returns only this user's records, so every sshd and sudo event
	is simply absent. That failure looks like a quiet server rather than an
	error, which is the worst way for a security tool to break — so the probe
	insists on seeing at least one root-owned record.
	"""
	if not shutil.which("journalctl"):
		return False
	try:
		result = subprocess.run(
			["journalctl", "--no-pager", "-o", "json", "-n", "20", "_UID=0"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=20,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return False
	return result.returncode == 0 and bool(result.stdout.strip())


def after_install():
	"""Seed settings, then tell the operator what still needs doing by hand."""
	_seed_settings()
	found = _scan_benches()
	report = check_prerequisites()
	_print_report(report, found)


def _seed_settings():
	"""Write the declared defaults into the Single so they are real values.

	A frappe Single applies DocType defaults only until something is written to
	it. Doing this at install time means the first write cannot silently blank
	every field nobody touched — see patches/seed_server_settings.py for the
	full account.
	"""
	from server.patches.seed_server_settings import execute as seed

	try:
		seed()
	except Exception:
		frappe.logger("server").warning("could not seed Server Settings defaults", exc_info=True)


def _scan_benches() -> int | None:
	"""Fill the bench table now, rather than at the top of the next hour.

	The scan is also scheduled hourly, so this is only about the first hour —
	but the first hour is when somebody opens the app to see whether installing
	it did anything. Returns None if it could not run; a failure here must not
	fail the install, because everything else about the app still works.
	"""
	from server.bench import discovery

	try:
		return int(discovery.scan_benches().get("found") or 0)
	except Exception:
		frappe.logger("server").warning("could not scan for benches at install", exc_info=True)
		return None


def _print_report(report: dict, benches: int | None = None):
	print("")
	print("  Server app installed.")
	print("")
	if benches:
		print(f"   ok benches      {benches} found")
	elif benches == 0:
		print("   !! benches      none found — check Bench Root in Server Settings")
	print("")
	for name, info in report["commands"].items():
		mark = "ok " if info["found"] else "!! "
		print(f"   {mark}{name:<12} {info['path'] or 'not found'}")

	logs = report["logs"]
	journal = "ok " if logs["journal_readable"] else "!! "
	auth = "ok " if logs["auth_log_readable"] else "!! "
	print(f"   {journal}journal      {'readable' if logs['journal_readable'] else 'not readable'}")
	print(
		f"   {auth}{logs['auth_log_path'] or 'auth log':<12} "
		f"{'readable' if logs['auth_log_readable'] else 'not readable'}"
	)

	for name, info in report.get("optional", {}).items():
		mark = "ok " if info["found"] else "-- "
		print(f"   {mark}{name:<12} {info['path'] or 'not installed (optional)'}")

	if report["problems"]:
		print("")
		print("  Before this can collect anything:")
		for problem in report["problems"]:
			print(f"   - {problem}")

	if report.get("notes"):
		print("")
		print("  Optional, only if you want the feature:")
		for note in report["notes"]:
			print(f"   - {note}")

	print("")
	print("  Next: open /serving, then turn on SSH Monitoring in Server Settings.")
	print("  App installs are blocked until you enable them there as well.")
	print("")
