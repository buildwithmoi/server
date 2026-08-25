# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What the web exposure means.

Two kinds of finding here, and they are graded differently on purpose.

The transport findings are absolute: a site served over plain HTTP is wrong
today, and no baseline makes it right. The guest-endpoint findings are
relative: fifty-five unauthenticated endpoints in frappe is not a defect, it
is how a web framework works -- login, ping, website rendering and password
reset all have to be reachable without a session. What matters is that the set
CHANGES, because an upgrade that adds one, or an app that adds one nobody
reviewed, moves the attack surface without anybody deciding to.

So the endpoints are inventoried and diffed rather than judged, and this app's
own two are named explicitly in the finding -- if the tool is going to report
on unauthenticated endpoints it should start by admitting to its own.
"""

from __future__ import annotations

from server.security import web
from server.security.rules import CRITICAL, HIGH, INFO, MEDIUM, Finding

CATEGORY = "web"


def _finding(severity: str, subject: str, detail: str, runbook: str) -> Finding:
	return Finding(severity, subject, detail, runbook, category=CATEGORY)


def judge_transport(frontends: list[web.Frontend]) -> list[Finding]:
	"""Whether traffic to this host is encrypted at all."""
	findings = []

	for frontend in frontends:
		name = frontend.path.rsplit("/", 1)[-1]
		served = ", ".join(frontend.server_names) or "an unnamed server block"

		if frontend.plaintext_only:
			findings.append(
				_finding(
					HIGH,
					f"{served} is served over plain HTTP only",
					f"{name} listens on {', '.join(str(p) for p in frontend.ports)} with no TLS. "
					f"Every session cookie, every password typed into a login form and every API "
					f"key sent to this site crosses the network in the clear, readable by anything "
					f"between the browser and this host.",
					"Run this app's SSL setup for the site, or `certbot --nginx` by hand. If this "
					"host is genuinely only reachable on a private network, the finding is still "
					"worth acting on: a stolen session cookie is the cheapest way into an "
					"application, and 'internal only' is an assumption that outlives the network "
					"it was true for.",
				)
			)

		if frontend.plaintext_only and "strict-transport-security" in frontend.headers:
			findings.append(
				_finding(
					MEDIUM,
					f"{served} sends an HSTS header over plain HTTP",
					"`Strict-Transport-Security` is set on a server block that does not serve TLS. "
					"Browsers ignore the header when it arrives over HTTP, so it is doing nothing "
					"— and its presence suggests the configuration was written expecting HTTPS "
					f"that was never finished. The policy also carries `preload` if unchanged, "
					f"which is a commitment that is hard to undo once a domain is submitted.",
					"Either finish the TLS setup, at which point the header starts working, or "
					"remove it. Sending it now mostly serves to make the configuration look more "
					"secure than it is.",
				)
			)

		weak = [p for p in frontend.tls_protocols if p in web.WEAK_TLS]
		if weak:
			findings.append(
				_finding(
					MEDIUM,
					f"{served} offers obsolete TLS versions",
					f"`ssl_protocols` includes {', '.join(weak)}. These are broken rather than "
					f"merely old.",
					"Set `ssl_protocols TLSv1.2 TLSv1.3;`. Nothing that can reach a modern frappe "
					"site is unable to speak TLS 1.2.",
				)
			)

		if frontend.serves_tls:
			missing = [h for h in web.EXPECTED_HEADERS if h not in frontend.headers]
			if missing:
				consequences = "; ".join(web.EXPECTED_HEADERS[h] for h in missing)
				findings.append(
					_finding(
						MEDIUM,
						f"{served} is missing {len(missing)} security header(s)",
						f"Not set: {', '.join(missing)}. Without them: {consequences}.",
						"Add them to the server block. Frappe's generated nginx config includes all "
						"four, so their absence usually means the config was hand-written or an "
						"older template was kept through an upgrade.",
					)
				)

	return findings


def judge_certificates(certificates: list[web.Certificate]) -> list[Finding]:
	"""How long until the site stops being reachable.

	An expired certificate is not a subtle security weakness — it is an
	outage, and one that arrives on a schedule everyone knew about.
	"""
	findings = []

	for certificate in certificates:
		if certificate.error:
			findings.append(
				_finding(
					MEDIUM,
					f"A TLS certificate could not be read: {certificate.path}",
					f"{certificate.error}. Its expiry date is therefore unknown, and expiry is the "
					f"most common way a working site stops working.",
					"Check the path in the nginx config points at a file this user can read. The "
					"certificate itself is public — it is the private key that is not — so reading "
					"it does not need root.",
				)
			)
			continue

		if certificate.days_remaining is None:
			continue

		if certificate.days_remaining < 0:
			findings.append(
				_finding(
					CRITICAL,
					f"The TLS certificate expired {abs(certificate.days_remaining)} days ago",
					f"{certificate.subject or certificate.path} is no longer valid. Browsers are "
					f"refusing the site, and automatic renewal has clearly not been working for at "
					f"least a month.",
					"Renew now: `certbot renew --force-renewal`, then find out why the timer did "
					"not. Note that this app never runs `bench renew-lets-encrypt`, which calls "
					"`click.confirm` with no non-interactive escape and aborts every time — the "
					"renewal path drives certbot directly.",
				)
			)
		elif certificate.days_remaining < web.CERT_WARN_DAYS:
			findings.append(
				_finding(
					HIGH,
					f"The TLS certificate expires in {certificate.days_remaining} days",
					f"{certificate.subject or certificate.path}. Certbot renews at 30 days, so "
					f"being inside {web.CERT_WARN_DAYS} means automatic renewal has already failed "
					f"more than once.",
					"Run `certbot renew` by hand and read the output — the usual causes are a "
					"webroot that moved, a DNS change, or nginx not reloading after a successful "
					"renewal, and each of them will recur next time.",
				)
			)

	return findings


def judge_endpoints(endpoints: list[web.Endpoint], previous: set[str] | None = None) -> list[Finding]:
	"""The unauthenticated attack surface, inventoried and diffed.

	Not judged by count. Fifty-five guest endpoints in frappe is how a web
	framework works, and a finding that fires on the framework's own login
	page teaches its reader that this category is noise.
	"""
	findings = []
	if not endpoints:
		return findings

	current = {e.dotted for e in endpoints}
	by_app: dict[str, int] = {}
	for endpoint in endpoints:
		by_app[endpoint.app] = by_app.get(endpoint.app, 0) + 1

	if previous is None:
		# First sight. Report the inventory once so somebody reads it, and
		# name this app's own endpoints rather than hiding among the rest.
		ours = sorted(e.dotted for e in endpoints if e.app == "server")
		breakdown = ", ".join(f"{app}: {count}" for app, count in sorted(by_app.items()))
		findings.append(
			_finding(
				INFO,
				f"{len(endpoints)} endpoints are callable without logging in",
				f"Across the installed apps ({breakdown}). This app contributes "
				f"{', '.join(ours) if ours else 'none'} — `security_heartbeat` is guest-reachable "
				f"on purpose so a machine elsewhere can poll it, and is gated by a token compared "
				f"in constant time; `get_context_for_dev` only responds while developer mode is on.",
				"No action. Recorded so that the next change to this set is visible as a change "
				"rather than as a number nobody had seen before.",
			)
		)
		return findings

	added = sorted(current - previous)
	removed = sorted(previous - current)

	if added:
		unguarded = [
			e.dotted for e in endpoints if e.dotted in set(added) and not e.rate_limited
		]
		findings.append(
			_finding(
				HIGH,
				f"{len(added)} new endpoint(s) became callable without logging in",
				f"{', '.join(added[:10])}. "
				+ (
					f"{len(unguarded)} of them have no rate limit."
					if unguarded
					else "All are rate limited."
				),
				"An app upgrade is the usual cause and is worth confirming — compare against what "
				"was installed and when. Read each one: an unauthenticated endpoint is reachable "
				"by anything that can reach the site, so it is code that must assume its caller is "
				"hostile.",
			)
		)

	if removed:
		findings.append(
			_finding(
				INFO,
				f"{len(removed)} endpoint(s) are no longer callable without logging in",
				f"{', '.join(removed[:10])}. The attack surface got smaller.",
				"No action. Recorded because the same mechanism that notices a surface growing "
				"should show it shrinking, or the record is only ever bad news.",
			)
		)

	return findings


def judge_coverage(surfaces: list) -> list[Finding]:
	blind = [s for s in surfaces if not s.readable]
	if not blind:
		return []

	paths = ", ".join(sorted({f"{s.path} ({s.reason})" for s in blind}))
	return [
		_finding(
			MEDIUM,
			"Part of the web configuration could not be read",
			f"Could not read: {paths}. TLS and header findings only cover the server blocks that "
			f"could be opened, so a clean report here covers less than it appears to.",
			"nginx configs are usually root-owned but world-readable; a config that is not is "
			"worth a NOPASSWD sudoers entry for a read-only helper rather than leaving the check "
			"blind.",
		)
	]


def judge(snapshot: web.Snapshot, previous_endpoints: set[str] | None = None) -> list[Finding]:
	findings: list[Finding] = []
	findings.extend(judge_transport(list(snapshot.frontends)))
	findings.extend(judge_certificates(list(snapshot.certificates)))
	findings.extend(judge_endpoints(list(snapshot.endpoints), previous_endpoints))
	findings.extend(judge_coverage(list(snapshot.surfaces)))
	return findings
