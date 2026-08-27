# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Let's Encrypt certificates for a bench's sites.

Two operations, matching the two things certbot is ever asked to do: issue a
certificate for a site that has none (or replace one that is broken), and renew
the certificates already on the box.

Neither maps cleanly onto a bench subcommand, and reading bench's own source is
what settled the design:

  * `bench renew-lets-encrypt` calls `click.confirm(..., abort=True)` with no
    non-interactive escape hatch (bench/config/lets_encrypt.py). Every job here
    runs with `stdin=DEVNULL`, so that command would abort 100% of the time.
    Renewal therefore drives certbot directly — which is exactly what bench's
    own cron entry does, so this is bench's real renewal path, minus the prompt.

  * `bench setup lets-encrypt` DOES take `-n`, so issuance uses it and gets
    bench's nginx rewriting and site_config bookkeeping for free.

Both need root, and neither is allowed to hang, so every command goes through
`sudo -n` — which fails immediately when a password would be required instead
of waiting forever for a tty that is not there.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field

MODE_ISSUE = "issue"
MODE_RENEW = "renew"
MODES = (MODE_ISSUE, MODE_RENEW)

#: Certbot is packaged three different ways and only one of them lands on a
#: worker's PATH. Checking the well-known locations turns "certbot: not found"
#: into a check that passes.
CERTBOT_CANDIDATES = ("/usr/bin/certbot", "/usr/local/bin/certbot", "/snap/bin/certbot")

#: `bench setup lets-encrypt` prints this and returns EXIT 0 when the bench is
#: not DNS-multitenant. Without matching on it, doing nothing at all reports as
#: success — the worst outcome available.
NO_MULTITENANCY = "You cannot setup SSL without DNS Multitenancy"

#: Same trap, other branches of the same function.
QUIET_FAILURES = (
	NO_MULTITENANCY,
	"There was a problem trying to setup SSL",
	"No site named",
	"No custom domain named",
)

#: A domain has to survive being passed to certbot and written into an nginx
#: config, so it is matched rather than escaped.
VALID_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

#: Issuance stops nginx, gets a certificate over the network and rewrites the
#: config. Ten minutes is generous for that and still bounded.
SSL_TIMEOUT = 900


class SSLRefused(Exception):
	"""Raised when the requested SSL operation cannot be built."""


@dataclass(frozen=True)
class Check:
	"""One readiness question, answered before anything is run."""

	key: str
	label: str
	ok: bool
	detail: str
	#: A failed blocking check stops the run. A failed advisory one is a warning:
	#: it is a reason this might not work, not proof that it cannot.
	blocking: bool = True


@dataclass(frozen=True)
class SiteSSL:
	"""What a site's certificate situation looks like right now."""

	site: str
	domain: str
	is_default: bool = False
	has_cert: bool = False
	expires_on: str | None = None
	days_left: int | None = None
	note: str = ""
	custom_domains: list[str] = field(default_factory=list)
	#: What DNS says about this site's domain, checked before certbot is asked.
	dns: dict = field(default_factory=dict)


# ----------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------


def certbot_path() -> str | None:
	"""Absolute path to certbot, or None.

	`shutil.which` first so a non-standard install still wins, then the known
	packaging locations because a worker's PATH is not a login shell's.
	"""
	found = shutil.which("certbot")
	if found:
		return found
	return next((p for p in CERTBOT_CANDIDATES if os.path.isfile(p) and os.access(p, os.X_OK)), None)


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
	"""Run a short read-only probe. Never raises, never blocks on input."""
	try:
		proc = subprocess.run(  # noqa: S603
			argv,
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=timeout,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		return 1, str(exc)
	return proc.returncode, f"{proc.stdout}\n{proc.stderr}".strip()


def has_passwordless_sudo() -> bool:
	"""True when sudo will run without asking for a password.

	`-n` is the whole point: it makes sudo fail instantly rather than sit on a
	password prompt that no one is there to answer.

	ASKS ABOUT THE COMMANDS THAT ARE ACTUALLY NEEDED, not about sudo in
	general. `sudo -n true` answers "can this user run ANYTHING as root", and a
	correctly narrow sudoers rule — NOPASSWD for certbot and nothing else — 
	fails it. So an operator who had done exactly the right thing was still
	told to add a rule they had already added, with the button still disabled.
	"""
	if _run(["sudo", "-n", "true"], timeout=5)[0] == 0:
		return True
	certbot = certbot_path()
	if not certbot:
		return False
	# The narrow grant. `--version` runs certbot for real but touches nothing.
	return _run(["sudo", "-n", certbot, "--version"], timeout=10)[0] == 0


#: A sudoers file that grants exactly what this app cannot do without, and
#: nothing else. Offered as text to install by hand: an app that could write
#: its own sudoers rule would not need one.
SUDOERS_PATH = "/etc/sudoers.d/frappe-server"


def sudoers_suggestion(user: str, certbot: str = "", bench_executable: str = "") -> str:
	"""The exact file, ready to paste, for the machine asking."""
	certbot = certbot or certbot_path() or "/usr/bin/certbot"
	bench_executable = bench_executable or "/usr/local/bin/bench"
	return "\n".join(
		[
			"# Granted by hand, deliberately: this app cannot grant itself root.",
			f"# Lives at {SUDOERS_PATH}, owned by root, mode 0440.",
			"#",
			"# Certificates. certbot binds port 80 and writes to /etc/letsencrypt.",
			f"{user} ALL=(root) NOPASSWD: {certbot}",
			"",
			"# Stopping and starting nginx around certbot. It authenticates with",
			"# --standalone, which wants the port nginx is holding — and these are",
			"# certbot's own pre and post hooks, so the start runs even when",
			"# issuing fails. Without the START granted, a failed certificate",
			"# takes every site on the machine offline.",
			f"{user} ALL=(root) NOPASSWD: /usr/bin/systemctl stop nginx",
			f"{user} ALL=(root) NOPASSWD: /usr/bin/systemctl start nginx",
			f"{user} ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx",
			"",
			"# Reloading nginx after a domain change.",
			f"{user} ALL=(root) NOPASSWD: {bench_executable} setup reload-nginx",
			f"{user} ALL=(root) NOPASSWD: /usr/sbin/nginx -t",
			"",
			"# Read-only, for the security detectors. Without these four,",
			"# sshd's effective config, password status, the firewall and the",
			"# root crontabs all report as unreadable rather than as clean.",
			f"{user} ALL=(root) NOPASSWD: /usr/sbin/sshd -T",
			f"{user} ALL=(root) NOPASSWD: /usr/bin/passwd -S -a",
			f"{user} ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose",
			f"{user} ALL=(root) NOPASSWD: /usr/bin/crontab -l -u root",
		]
	)


def _read_json(path: str) -> dict:
	try:
		with open(path) as handle:
			return json.load(handle) or {}
	except (OSError, ValueError):
		return {}


def is_dns_multitenant(bench_path: str) -> bool:
	config = _read_json(os.path.join(bench_path, "sites", "common_site_config.json"))
	return bool(config.get("dns_multitenant"))


def site_domains(bench_path: str, site: str) -> tuple[str, list[str]]:
	"""The site's primary domain and any extra domains configured for it.

	A site is usually reachable at its own name, but `host_name` overrides that
	and `domains` adds more. Certbot needs the name people actually type, so
	guessing from the directory name alone would issue the wrong certificate.
	"""
	config = _read_json(os.path.join(bench_path, "sites", site, "site_config.json"))

	host = (config.get("host_name") or "").strip()
	host = re.sub(r"^https?://", "", host).rstrip("/") if host else ""

	extras: list[str] = []
	for entry in config.get("domains") or []:
		name = entry.get("domain") if isinstance(entry, dict) else entry
		if name:
			extras.append(str(name))

	return host or site, extras


def installed_certificates() -> tuple[dict[str, dict], str]:
	"""Every certificate certbot knows about, keyed by domain.

	`/etc/letsencrypt/{accounts,archive,keys}` are mode 0700, so reading the
	directory tree as the bench user does not work. Asking certbot is the only
	reliable way, and it needs sudo — when that is unavailable the honest answer
	is "unknown", not "none".
	"""
	certbot = certbot_path()
	if not certbot:
		return {}, "certbot is not installed."
	if not has_passwordless_sudo():
		return {}, "Needs sudo to read — status will be confirmed when you run it."

	code, out = _run(["sudo", "-n", certbot, "certificates"], timeout=20)
	if code != 0:
		return {}, "certbot could not list certificates."

	certs: dict[str, dict] = {}
	current: dict | None = None
	for raw in out.splitlines():
		line = raw.strip()
		if line.startswith("Certificate Name:"):
			current = {"name": line.split(":", 1)[1].strip(), "domains": [], "expiry": None, "days": None}
		elif current is None:
			continue
		elif line.startswith("Domains:"):
			current["domains"] = line.split(":", 1)[1].split()
		elif line.startswith("Expiry Date:"):
			value = line.split(":", 1)[1].strip()
			current["expiry"] = value.split(" (")[0].strip()
			# certbot prints "VALID: N day(s)" and, under 24 hours, "VALID: N
			# hour(s)". Matching only days meant a certificate with hours left
			# reported as days=None — rendered as neutral, when it is the most
			# urgent state there is.
			match = re.search(r"VALID:\s*(\d+)\s*(day|hour|minute)", value)
			if match:
				# Anything under a day is 0 days: "expires today".
				current["days"] = int(match.group(1)) if match.group(2) == "day" else 0
			else:
				current["days"] = 0 if "INVALID" in value else None
			for domain in current["domains"]:
				certs[domain] = current

	return certs, ""


# ----------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------


def local_ips() -> set[str]:
	"""Every IPv4 address this machine answers on.

	Two sources because neither is complete on its own: `hostname -I` lists the
	configured addresses, and the UDP trick finds the one the kernel would
	actually route out of — which is the one that matters and which is missing
	from the first list on some setups. No packet is sent; connect() on a UDP
	socket only fixes the route.
	"""
	found: set[str] = set()

	code, out = _run(["hostname", "-I"], timeout=5)
	if code == 0:
		found.update(part for part in out.split() if part.count(".") == 3)

	try:
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
			probe.settimeout(2)
			probe.connect(("198.51.100.1", 53))
			found.add(probe.getsockname()[0])
	except OSError:
		pass

	return found


def resolve(domain: str) -> list[str]:
	"""The A records for a domain, or an empty list if it does not resolve."""
	try:
		infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
	except (OSError, UnicodeError):
		return []
	return sorted({info[4][0] for info in infos})


def dns_check(domain: str) -> dict:
	"""Does this domain point at this machine?

	The check certbot will effectively perform, done first and for free. Let's
	Encrypt rate-limits failed authorisations per account and the block outlasts
	the mistake, so burning an attempt on a domain whose DNS was never pointed
	here is the single most avoidable way to lock yourself out.

	Deliberately advisory. A server behind a proxy, a load balancer or Cloudflare
	genuinely does not resolve to its own address, and refusing those outright
	would be wrong.
	"""
	if not VALID_DOMAIN.match(domain or ""):
		return {
			"domain": domain,
			"resolved": [],
			"points_here": False,
			"level": "danger",
			"detail": f"{domain} is not a public domain name, so Let's Encrypt cannot certify it.",
		}

	addresses = resolve(domain)
	if not addresses:
		return {
			"domain": domain,
			"resolved": [],
			"points_here": False,
			"level": "danger",
			"detail": (
				f"{domain} does not resolve. Point an A record at this server and wait for it to "
				"propagate — certbot will fail until it does."
			),
		}

	mine = local_ips()
	if mine & set(addresses):
		return {
			"domain": domain,
			"resolved": addresses,
			"points_here": True,
			"level": "ok",
			"detail": f"{domain} resolves to this server ({', '.join(sorted(mine & set(addresses)))}).",
		}

	return {
		"domain": domain,
		"resolved": addresses,
		"points_here": False,
		"level": "warn",
		"detail": (
			f"{domain} resolves to {', '.join(addresses)}, which is not an address on this machine "
			f"({', '.join(sorted(mine)) or 'none detected'}). That is expected behind a proxy or "
			"Cloudflare; otherwise certbot will fail to validate."
		),
	}


# ----------------------------------------------------------------------
# Readiness
# ----------------------------------------------------------------------


def sudoers_install_command(user: str, certbot: str = "", bench_executable: str = "") -> str:
	"""One command that writes the file, checks it, and only then installs it.

	THE FILE IS NOT A THING YOU CAN PASTE INTO A SHELL. It was offered as one,
	and it was — `erpnext ALL=(root) NOPASSWD: ...` is eight lines of syntax
	error in bash, which is what the operator got, eight times.

	Written to a `.tmp` name first and validated with `visudo -c` before it is
	moved into place. sudo ignores files in sudoers.d whose names contain a
	dot, so the half-written one is inert while it is being checked — and a
	broken sudoers file is the one mistake here that locks somebody out of
	their own machine.
	"""
	body = sudoers_suggestion(user, certbot, bench_executable)
	temporary = f"{SUDOERS_PATH}.tmp"
	return "\n".join(
		[
			f"sudo tee {temporary} > /dev/null <<'SUDOERS'",
			body,
			"SUDOERS",
			f"sudo chmod 0440 {temporary}",
			f"sudo visudo -c -f {temporary} && sudo mv {temporary} {SUDOERS_PATH} "
			f"|| sudo rm -f {temporary}",
		]
	)


def readiness(bench_path: str, sites: list[dict]) -> dict:
	"""Answer every question that can be answered without touching the network.

	The point is to fail in a dialog in under a second rather than three minutes
	into a subprocess, and — when it will not work — to say which of the four
	usual reasons applies.
	"""
	certbot = certbot_path()
	sudo_ok = has_passwordless_sudo()
	multitenant = is_dns_multitenant(bench_path)

	checks = [
		Check(
			key="certbot",
			label="certbot installed",
			ok=bool(certbot),
			detail=certbot or "Not found. Install it with: sudo apt install certbot python3-certbot-nginx",
		),
		Check(
			key="sudo",
			label="root for certbot",
			ok=sudo_ok,
			detail=(
				"Available."
				if sudo_ok
				else "certbot binds port 80 and writes to /etc/letsencrypt, and a job has no "
				"terminal to type a password into. This is the one thing here that cannot be "
				"worked around: the app runs as the bench user, which is what makes it safe to "
				"give a web interface at all. The sudoers file below grants exactly what is "
				"needed and nothing else."
			),
		),
		Check(
			key="multitenant",
			label="DNS multitenancy",
			ok=multitenant,
			detail=(
				"Enabled."
				if multitenant
				else "Off. bench refuses to set up SSL without it — and exits 0 while refusing, "
				"so it would look like it worked. This job turns it on before it starts, along "
				"with adding the domain to the site and regenerating the nginx config."
			),
			# NOT blocking. It was, and the panel then told the operator to run
			# `bench config dns_multitenant on` themselves, per bench, before
			# coming back — which is a page refusing to do the thing it knows
			# how to do. The job does it now, so this is a note about what is
			# going to happen rather than a reason to refuse.
			blocking=False,
		),
	]

	certs, cert_note = installed_certificates()

	rows: list[SiteSSL] = []
	for site in sites:
		name = site["name"] if isinstance(site, dict) else str(site)
		is_default = bool(site.get("is_default")) if isinstance(site, dict) else False
		domain, extras = site_domains(bench_path, name)
		cert = certs.get(domain)
		rows.append(
			SiteSSL(
				dns=dns_check(domain),
				site=name,
				domain=domain,
				is_default=is_default,
				has_cert=bool(cert),
				expires_on=cert["expiry"] if cert else None,
				days_left=cert["days"] if cert else None,
				note=_site_note(domain, cert, cert_note),
				custom_domains=extras,
			)
		)

	return {
		"checks": [check.__dict__ for check in checks],
		"sites": [row.__dict__ for row in rows],
		"ready": all(check.ok for check in checks if check.blocking),
		"certificates_note": cert_note,
		# The exact file, for this machine, ready to paste. Only when it would
		# change anything — a panel that offers a fix for a problem nobody has
		# is the same noise as a warning nobody needs.
		"sudoers": "" if sudo_ok else sudoers_suggestion(_current_user(), certbot or ""),
		# What to actually paste. The file itself is not a shell script, and
		# offering it as though it were produced eight syntax errors in a row.
		"sudoers_command": (
			"" if sudo_ok else sudoers_install_command(_current_user(), certbot or "")
		),
		"sudoers_path": SUDOERS_PATH,
	}


def _current_user() -> str:
	"""Whose sudoers rule it would have to be."""
	import getpass

	try:
		return getpass.getuser()
	except Exception:  # noqa: BLE001
		return "$USER"


def _site_note(domain: str, cert: dict | None, cert_note: str) -> str:
	"""One line saying what this site needs, in the order it becomes true."""
	if not VALID_DOMAIN.match(domain):
		return f"{domain} is not a public domain name — Let's Encrypt cannot certify it."
	if cert_note:
		return cert_note
	if not cert:
		return "No certificate yet."
	days = cert.get("days")
	if days is None:
		return f"Certificate expires {cert['expiry']}."
	if days <= 0:
		return "Certificate has EXPIRED."
	if days <= 30:
		return f"Expires in {days} days — inside the renewal window."
	return f"Valid for another {days} days."


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------


def build_argv(
	mode: str,
	bench_exe: str,
	site: str | None = None,
	custom_domain: str | None = None,
	dry_run: bool = False,
	email: str = "",
) -> list[str]:
	"""The exact argv for one SSL operation.

	A list, never a string, and never through a shell — the domain arrives from
	a browser.
	"""
	if mode not in MODES:
		raise SSLRefused(f"{mode!r} is not an SSL operation.")

	if mode == MODE_ISSUE:
		if not site:
			raise SSLRefused("Issuing a certificate needs a site.")

		target = (custom_domain or site).strip()
		if custom_domain and not VALID_DOMAIN.match(target):
			raise SSLRefused(f"{target!r} is not a valid domain name.")

		certbot = certbot_path()
		if not certbot:
			raise SSLRefused("certbot is not installed, so there is nothing to issue with.")

		# CERTBOT DIRECTLY, not `bench setup lets-encrypt`.
		#
		# bench's own path is written to be run AS ROOT, not by a user with a
		# narrow grant: it writes /etc/letsencrypt/configs/<domain>.cfg with no
		# sudo at all, and runs certbot with no sudo either. As the bench user
		# it fails on the first mkdir. Making it work would mean granting
		# `sudo bench setup lets-encrypt *` — a wildcard on a command that
		# takes a site name from a browser, which is a root shell with extra
		# steps.
		#
		# So this does what the RENEWAL path here already does, for the same
		# reasons, and installs the certificate itself afterwards.
		argv = [
			"sudo",
			"-n",
			certbot,
			"certonly",
			"--non-interactive",
			"--agree-tos",
			# Matching bench's own template, so a certificate issued here and
			# one issued by bench are the same shape.
			"--key-type",
			"ecdsa",
			"--elliptic-curve",
			"secp384r1",
			"--standalone",
			# Hooks rather than three sequential commands: certbot runs the
			# post-hook even when issuing FAILS, so nginx cannot be left down
			# by an error. Sequential is what bench does, and it is why a
			# failed issue there takes every site offline until somebody
			# notices.
			"--pre-hook",
			"systemctl stop nginx",
			"--post-hook",
			"systemctl start nginx",
			"-d",
			target,
		]
		if email and "@" in email:
			argv += ["--email", email]
		else:
			# Let's Encrypt allows it, and it is better than inventing an
			# address that expiry warnings will be sent to.
			argv.append("--register-unsafely-without-email")
		if dry_run:
			argv.append("--dry-run")
		return argv

	certbot = certbot_path()
	if not certbot:
		raise SSLRefused("certbot is not installed, so there is nothing to renew with.")

	# bench issues with `authenticator = standalone`, which wants port 443 to
	# itself — so nginx has to be down for the renewal and up again after.
	# Hooks rather than three sequential commands: certbot runs the post-hook
	# even when renewal fails, so nginx cannot be left down by an error. Doing
	# it in sequence is what bench's own renew_certs does, and it is why a
	# failed renewal there takes the sites offline until someone notices.
	argv = [
		"sudo",
		"-n",
		certbot,
		"renew",
		"--pre-hook",
		"systemctl stop nginx",
		"--post-hook",
		"systemctl start nginx",
	]
	if dry_run:
		# Let's Encrypt bans an IP after enough failures, and the ban outlasts
		# the mistake. A dry run against the staging server costs nothing.
		argv.append("--dry-run")
	return argv


def certificate_paths(target: str) -> dict:
	"""Where certbot puts a certificate for `target`.

	The same two paths bench writes into a site config, so a site certified
	here and one certified by bench are configured identically.
	"""
	live = f"/etc/letsencrypt/live/{target}"
	return {
		"ssl_certificate": f"{live}/fullchain.pem",
		"ssl_certificate_key": f"{live}/privkey.pem",
	}


def describe(mode: str, site: str | None, custom_domain: str | None, dry_run: bool) -> str:
	"""Plain-language summary of what pressing the button will do."""
	if mode == MODE_ISSUE:
		target = custom_domain or site
		return (
			f"Turn on DNS multitenancy if it is off, add {target} to the site, rebuild the nginx "
			f"config, then stop nginx, ask Let's Encrypt for a certificate for {target}, start "
			"nginx again, point the site at the certificate and reload."
		)
	if dry_run:
		return (
			"Rehearse renewal against Let's Encrypt's staging server. Nothing is installed and no "
			"rate limit is consumed — this only proves renewal would work."
		)
	return (
		"Renew every certificate that is inside its renewal window. nginx stops for the check and "
		"starts again afterwards, even if renewal fails."
	)


def quiet_failure(output: str) -> str | None:
	"""Detect the failures bench reports by printing and then exiting 0.

	Without this, "you cannot setup SSL without DNS multitenancy" is recorded as
	a successful run, and the site quietly stays on plain HTTP.
	"""
	for marker in QUIET_FAILURES:
		if marker in output:
			if marker == NO_MULTITENANCY:
				return (
					"bench refused: this bench is not DNS-multitenant, so it will not set up SSL. "
					"Enable it with `bench config dns_multitenant on`, make sure the site is "
					"reachable at its domain, then try again."
				)
			line = next((row.strip() for row in output.splitlines() if marker in row), marker)
			return f"bench reported a problem and stopped: {line}"
	return None
