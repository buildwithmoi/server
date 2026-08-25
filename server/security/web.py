# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What this host exposes to the internet, and on what terms.

`network.py` answers which ports are open. This answers what is actually
listening on them: whether the site is served over TLS at all, what the
certificate looks like, which security headers the proxy sets, and -- the part
nobody audits -- exactly which application endpoints can be called with no
session at all.

THE GUEST ENDPOINT INVENTORY IS THE INTERESTING HALF. A frappe bench's real
attack surface is not its open ports, which are two, but its
`allow_guest=True` methods, which are dozens, come from every installed app,
and change whenever one is upgraded. They are enumerated from SOURCE rather
than from `frappe.whitelisted`, because that registry is populated lazily as
modules are imported -- asking it at runtime returned four on this box, where
the source holds fifty-seven. A check that under-reports the attack surface by
an order of magnitude is worse than no check.

Scoped to INSTALLED apps, not to what is on disk. This bench has press and
erpnext in `apps/` and neither is installed on the site, so their hundred and
ten guest endpoints are not reachable and counting them would be a hundred and
ten lies.

Frappe-free: it parses files. The list of installed apps is passed in.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field

from server.security.persistence import Surface

KIND_TLS = "tls"
KIND_HEADERS = "headers"
KIND_ENDPOINTS = "guest-endpoints"

#: Headers a public site should be setting. Values are what to say when one is
#: missing -- the consequence, not the specification.
EXPECTED_HEADERS = {
	"x-frame-options": "the site can be framed by another origin, which is how clickjacking works",
	"x-content-type-options": "browsers may guess at content types and execute an upload as script",
	"strict-transport-security": "a browser that has visited over HTTPS can still be downgraded to HTTP",
	"referrer-policy": "full URLs, including any token in them, are sent to every site linked to",
}

#: TLS versions that should no longer be offered.
WEAK_TLS = ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")

#: Warn this far ahead of expiry. Certbot renews at 30 days, so 21 means the
#: alert fires only once automatic renewal has already failed twice.
CERT_WARN_DAYS = 21

_LISTEN = re.compile(r"^\s*listen\s+(?P<value>[^;]+);", re.MULTILINE)
_HEADER = re.compile(r"^\s*add_header\s+(?P<name>[A-Za-z-]+)\s+(?P<value>.+?);", re.MULTILINE)
_SSL_CERT = re.compile(r"^\s*ssl_certificate\s+(?P<path>[^;]+);", re.MULTILINE)
_SSL_PROTOCOLS = re.compile(r"^\s*ssl_protocols\s+(?P<value>[^;]+);", re.MULTILINE)
_SERVER_NAME = re.compile(r"^\s*server_name\s+(?P<value>[^;]+);", re.MULTILINE | re.DOTALL)


@dataclass(frozen=True)
class Endpoint:
	"""One application method callable without logging in."""

	app: str
	module: str
	function: str
	#: True when the decorator also restricts the HTTP methods.
	restricted_methods: bool = False
	#: True when frappe's rate limiter is applied to it.
	rate_limited: bool = False

	@property
	def dotted(self) -> str:
		return f"{self.module}.{self.function}"


@dataclass(frozen=True)
class Frontend:
	"""One nginx server block, described."""

	path: str
	ports: tuple[int, ...] = ()
	serves_tls: bool = False
	server_names: tuple[str, ...] = ()
	headers: dict = field(default_factory=dict)
	certificate: str = ""
	tls_protocols: tuple[str, ...] = ()
	#: SHA-256 of the file, so a change is answerable without storing it. An
	#: nginx config names internal upstreams and file paths; the hash answers
	#: "did this change" and nothing else.
	config_hash: str = ""

	@property
	def plaintext_only(self) -> bool:
		return bool(self.ports) and not self.serves_tls


@dataclass(frozen=True)
class Certificate:
	path: str
	days_remaining: int | None = None
	subject: str = ""
	error: str = ""


@dataclass(frozen=True)
class Snapshot:
	frontends: tuple[Frontend, ...] = ()
	certificates: tuple[Certificate, ...] = ()
	endpoints: tuple[Endpoint, ...] = ()
	surfaces: tuple[Surface, ...] = ()


# ----------------------------------------------------------------------
# The proxy in front
# ----------------------------------------------------------------------


def parse_nginx(text: str, path: str = "") -> Frontend:
	"""Pull the security-relevant directives out of an nginx config.

	Deliberately not a full nginx parser. Everything below is a directive
	whose absence or presence is the finding, and a grammar for the whole
	configuration language would be a large amount of code standing between
	this app and four questions.
	"""
	ports: list[int] = []
	serves_tls = False
	for match in _LISTEN.finditer(text):
		value = match.group("value").strip()
		if "ssl" in value.split():
			serves_tls = True
		number = re.search(r"(?:^|:)(\d+)", value)
		if number:
			ports.append(int(number.group(1)))

	headers = {
		match.group("name").lower(): match.group("value").strip().strip('"')
		for match in _HEADER.finditer(text)
	}

	certificate = ""
	cert_match = _SSL_CERT.search(text)
	if cert_match:
		certificate = cert_match.group("path").strip()
		serves_tls = True

	protocols: tuple[str, ...] = ()
	protocol_match = _SSL_PROTOCOLS.search(text)
	if protocol_match:
		protocols = tuple(protocol_match.group("value").split())

	names: list[str] = []
	name_match = _SERVER_NAME.search(text)
	if name_match:
		names = [n for n in name_match.group("value").split() if n and n != "_"]

	return Frontend(
		path=path,
		config_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
		ports=tuple(sorted(set(ports))),
		serves_tls=serves_tls,
		server_names=tuple(names),
		headers=headers,
		certificate=certificate,
		tls_protocols=protocols,
	)


def collect_frontends(directories: tuple[str, ...] = ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled")) -> tuple[list[Frontend], list[Surface]]:
	frontends: list[Frontend] = []
	surfaces: list[Surface] = []

	for directory in directories:
		if not os.path.isdir(directory):
			surfaces.append(Surface(KIND_HEADERS, directory, True, "not present", 0))
			continue
		try:
			names = sorted(os.listdir(directory))
		except OSError as exc:
			surfaces.append(Surface(KIND_HEADERS, directory, False, str(exc), 0))
			continue

		found = 0
		for name in names:
			path = os.path.join(directory, name)
			try:
				with open(path, encoding="utf-8", errors="replace") as handle:
					text = handle.read()
			except OSError as exc:
				surfaces.append(Surface(KIND_HEADERS, path, False, str(exc), 0))
				continue
			frontends.append(parse_nginx(text, path))
			found += 1
		surfaces.append(Surface(KIND_HEADERS, directory, True, "", found))

	return frontends, surfaces


def read_certificate(path: str) -> Certificate:
	"""How long the certificate has left.

	Shells out to openssl rather than parsing X.509, because Python has no
	public certificate parser and a hand-rolled DER reader is a great deal of
	code to answer one date.
	"""
	if not path or not os.path.exists(path):
		return Certificate(path=path, error="certificate file not readable")

	try:
		result = subprocess.run(  # noqa: S603
			["openssl", "x509", "-in", path, "-noout", "-enddate", "-subject"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=20,
			check=False,
		)
	except FileNotFoundError:
		return Certificate(path=path, error="openssl is not installed")
	except (OSError, subprocess.SubprocessError) as exc:
		return Certificate(path=path, error=str(exc))

	if result.returncode != 0:
		return Certificate(path=path, error=(result.stderr or "").strip()[:200])

	return _parse_certificate(result.stdout, path)


def _parse_certificate(text: str, path: str) -> Certificate:
	"""Parse `openssl x509 -enddate -subject` output. Pure, so it is testable."""
	from datetime import datetime, timezone

	days = None
	subject = ""
	for line in text.splitlines():
		if line.startswith("notAfter="):
			stamp = line.split("=", 1)[1].strip()
			for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
				try:
					expiry = datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
				except ValueError:
					continue
				days = (expiry - datetime.now(timezone.utc)).days
				break
		elif line.startswith("subject="):
			subject = line.split("=", 1)[1].strip()

	return Certificate(path=path, days_remaining=days, subject=subject)


# ----------------------------------------------------------------------
# The application behind it
# ----------------------------------------------------------------------


def _guest_endpoints_in(path: str, app: str) -> list[Endpoint]:
	"""Every `@frappe.whitelist(allow_guest=True)` in one file."""
	try:
		# Closed explicitly: this walks every .py file in every installed app,
		# so a leaked descriptor per file is thousands of them per scan.
		with open(path, encoding="utf-8", errors="replace") as handle:
			tree = ast.parse(handle.read())
	except (OSError, SyntaxError, ValueError):
		return []

	relative = path.split(f"/apps/{app}/", 1)[-1].removesuffix(".py").replace("/", ".")
	found = []
	for node in ast.walk(tree):
		if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
			continue

		guest = False
		restricted = False
		limited = any(
			getattr(getattr(d, "func", d), "attr", getattr(getattr(d, "func", d), "id", "")) == "rate_limit"
			for d in node.decorator_list
		)
		for decorator in node.decorator_list:
			if not isinstance(decorator, ast.Call):
				continue
			name = getattr(decorator.func, "attr", getattr(decorator.func, "id", ""))
			if name != "whitelist":
				continue
			for keyword in decorator.keywords:
				if keyword.arg == "allow_guest" and isinstance(keyword.value, ast.Constant):
					guest = bool(keyword.value.value)
				if keyword.arg == "methods":
					restricted = True

		if guest:
			found.append(
				Endpoint(
					app=app,
					module=relative,
					function=node.name,
					restricted_methods=restricted,
					rate_limited=limited,
				)
			)
	return found


def collect_endpoints(apps_path: str, installed: list[str]) -> tuple[list[Endpoint], list[Surface]]:
	"""Guest-callable endpoints, for INSTALLED apps only.

	An app sitting in `apps/` that is not installed on any site serves nothing.
	Counting it would inflate the reported attack surface with code that
	cannot be reached, which is the same failure as under-reporting it.
	"""
	endpoints: list[Endpoint] = []
	surfaces: list[Surface] = []

	for app in installed:
		root = os.path.join(apps_path, app)
		if not os.path.isdir(root):
			surfaces.append(Surface(KIND_ENDPOINTS, root, False, "installed app not found on disk", 0))
			continue

		found: list[Endpoint] = []
		for directory, dirnames, filenames in os.walk(root):
			dirnames[:] = [
				d for d in dirnames if d not in ("node_modules", "__pycache__", ".git", "tests", "test")
			]
			for filename in filenames:
				if filename.endswith(".py"):
					found.extend(_guest_endpoints_in(os.path.join(directory, filename), app))
		endpoints.extend(found)
		surfaces.append(Surface(KIND_ENDPOINTS, app, True, "", len(found)))

	return endpoints, surfaces


def collect(apps_path: str, installed: list[str]) -> Snapshot:
	frontends, frontend_surfaces = collect_frontends()
	endpoints, endpoint_surfaces = collect_endpoints(apps_path, installed)

	certificates = []
	for frontend in frontends:
		if frontend.certificate:
			certificates.append(read_certificate(frontend.certificate))

	return Snapshot(
		frontends=tuple(frontends),
		certificates=tuple(certificates),
		endpoints=tuple(endpoints),
		surfaces=tuple(frontend_surfaces + endpoint_surfaces),
	)
