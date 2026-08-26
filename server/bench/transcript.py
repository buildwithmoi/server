# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Turning a finished job into a document somebody can read, keep or send.

A deployment that went wrong is usually diagnosed by somebody who was not
watching it happen — often days later, often not the person who ran it. What
they need is one self-contained thing: what was asked for, who asked, when,
which step it died on, and the whole output with nothing trimmed.

WHY THIS IS NOT JUST `output`. The raw log is the largest part but it is the
least useful on its own — it opens mid-clone with no indication of which bench,
which frappe version, which apps, or whether the step that failed was the fifth
of nine or the last. The header and the step table are what make the log
answerable without going back to the database to look up the request.

Frappe-free: it takes plain dicts and returns text, so the formatting is
testable and the same function serves the copy button, the download and
anything that later wants to attach one to an alert.
"""

from __future__ import annotations

#: Wide enough for a step title plus timing without wrapping in a terminal.
RULE = "─" * 72


def _duration(seconds) -> str:
	try:
		total = int(float(seconds or 0))
	except (TypeError, ValueError):
		return "—"
	if total <= 0:
		return "—"
	if total < 60:
		return f"{total}s"
	minutes, rest = divmod(total, 60)
	if minutes < 60:
		return f"{minutes}m {rest:02d}s"
	hours, minutes = divmod(minutes, 60)
	return f"{hours}h {minutes:02d}m"


def _row(label: str, value) -> str:
	text = "" if value is None else str(value).strip()
	return f"{label:<18} {text or '—'}"


def build(request: dict, steps: list[dict] | None = None) -> str:
	"""One plain-text transcript of a deployment.

	Plain text rather than JSON or HTML on purpose: it has to survive being
	pasted into a chat window, an email or an issue, which is what actually
	happens to it.
	"""
	steps = steps or []
	lines: list[str] = []

	title = request.get("app_name") or request.get("operation") or "Job"
	lines += [RULE, f"  {title}", RULE, ""]

	lines += [
		_row("Request", request.get("name")),
		_row("Operation", request.get("operation")),
		_row("Host", request.get("host") or ""),
		_row("Bench", request.get("provision_bench_name") or request.get("bench")),
	]

	if request.get("provision_site_name"):
		lines.append(_row("Site", request["provision_site_name"]))
	if request.get("provision_frappe_version"):
		lines.append(_row("Frappe", f"version-{request['provision_frappe_version']}"))
	if request.get("provision_port_index"):
		index = int(request["provision_port_index"])
		lines.append(_row("Ports", f"web {8000 + index}, socketio {9000 + index}"))
	if request.get("provision_apps"):
		apps = [line for line in str(request["provision_apps"]).splitlines() if line.strip()]
		lines.append(_row("Apps", ", ".join(a.replace("|", ":") for a in apps) or "frappe only"))
	if request.get("provision_domain"):
		lines.append(_row("Domain", request["provision_domain"]))

	lines += [
		"",
		# Who and when are the two questions a log nobody was watching always
		# raises first, so they sit above the outcome rather than in a footer.
		_row("Started by", request.get("owner")),
		_row("Started", request.get("started_at") or request.get("creation")),
		_row("Finished", request.get("finished_at")),
		_row("Took", _duration(request.get("duration"))),
		_row("Outcome", request.get("status")),
		_row("Exit code", request.get("exit_code")),
	]

	if request.get("error_summary"):
		lines += ["", "Why it stopped", "", f"  {request['error_summary'].strip()}"]

	if steps:
		lines += ["", RULE, "  Steps", RULE, ""]
		for step in steps:
			mark = {
				"Success": "ok  ",
				"Failure": "FAIL",
				"Running": "... ",
				"Skipped": "skip",
			}.get(step.get("status"), "    ")
			took = _duration(step.get("duration"))
			lines.append(f"  [{mark}] {str(step.get('title') or step.get('key')):<44} {took}")
			if step.get("detail"):
				lines.append(f"          {step['detail']}")

	if request.get("command"):
		lines += ["", RULE, "  Last command", RULE, "", f"  $ {request['command']}"]

	lines += ["", RULE, "  Output", RULE, ""]
	output = (request.get("output") or "").rstrip()
	lines.append(output if output else "  (nothing was captured)")
	lines.append("")

	return "\n".join(lines)


def filename(request: dict) -> str:
	"""A filename that sorts and says what it is, with nothing secret in it."""
	stamp = str(request.get("started_at") or request.get("creation") or "")[:19]
	stamp = stamp.replace(" ", "_").replace(":", "").replace("-", "")
	bench = request.get("provision_bench_name") or request.get("bench") or "job"
	safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in str(bench))
	return f"{stamp or 'deployment'}-{safe}-{request.get('name', 'log')}.txt"
