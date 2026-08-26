# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A long operation as a list of named steps.

Every bench operation used to present itself as one scrolling wall of
subprocess output. That is fine when it works and close to useless when it does
not: "it failed" and 900 lines of git chatter does not tell you *which part*
failed, and there is no way to see how far it got before it stopped.

Frappe Cloud's own dashboard solves this by breaking each remote job into named
steps and folding the output under each one (`AgentJobStep`, rendered by
`FoldStep.vue`). The same idea fits here, and it buys two things beyond
prettiness:

  * the plan is announced BEFORE the work starts, so you can see that a restore
    is about to take a backup first — while there is still time to cancel;
  * a failure is attributed. "Clone the app" failing and "Install on the site"
    failing are completely different problems with completely different fixes.

Frappe-free on purpose, like `ssh/parser.py`: the state machine is the part
worth testing, and it tests with no site and no database.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

PENDING = "Pending"
RUNNING = "Running"
SUCCESS = "Success"
FAILURE = "Failure"
SKIPPED = "Skipped"

#: Terminal states — a step in one of these is never written to again.
DONE = (SUCCESS, FAILURE, SKIPPED)

#: Output kept per step. The complete log still lives in `output`; this is the
#: excerpt folded under the step, and a git clone can emit tens of thousands of
#: progress lines that nobody will scroll through.
MAX_STEP_LINES = 400

#: Identifies the marker line so it is never counted as output.
_TRUNCATION_PREFIX = "… "


@dataclass
class Step:
	"""One named unit of work within an operation."""

	key: str
	title: str
	description: str = ""
	status: str = PENDING
	detail: str = ""
	output: list[str] = field(default_factory=list)
	#: Cumulative lines discarded from this step's output. Tracked on the step
	#: rather than recomputed from the list, which could only ever report the
	#: size of the last trim.
	dropped: int = 0
	started_at: str | None = None
	finished_at: str | None = None
	duration: float | None = None

	def as_dict(self) -> dict:
		return {
			"key": self.key,
			"title": self.title,
			"description": self.description,
			"status": self.status,
			"detail": self.detail,
			"output": "\n".join(self.output),
			"dropped": self.dropped,
			"started_at": self.started_at,
			"finished_at": self.finished_at,
			"duration": self.duration,
		}


class Plan:
	"""The steps of one operation, and where it has got to.

	Announced in full up front — every step exists in `Pending` from the moment
	the job starts, so the interface can show what is going to happen rather
	than growing a list as it goes.
	"""

	def __init__(self, steps: list[Step], now: Callable[[], datetime] | None = None):
		self.steps = steps
		self._now = now or datetime.now
		self._current: str | None = None

	# ------------------------------------------------------------------

	def get(self, key: str) -> Step | None:
		return next((s for s in self.steps if s.key == key), None)

	@property
	def current(self) -> Step | None:
		return self.get(self._current) if self._current else None

	def start(self, key: str) -> Step:
		"""Begin a step, closing off any that was running.

		Closing the previous one matters: a job that moves on without saying so
		would leave a step spinning forever in the interface.
		"""
		if self._current and self._current != key:
			previous = self.current
			if previous and previous.status == RUNNING:
				self.succeed(self._current)

		step = self.get(key)
		if step is None:
			# An unplanned step is still worth showing. Better a step that was
			# not announced than work that happens invisibly.
			step = Step(key=key, title=key)
			self.steps.append(step)

		step.status = RUNNING
		step.started_at = self._stamp()
		self._current = key
		return step

	def line(self, text: str) -> None:
		"""Attach a line of output to whatever is running."""
		step = self.current
		if step is None or step.status in DONE:
			return
		step.output.append(text)
		if len(step.output) <= MAX_STEP_LINES:
			return

		# Keep the tail: the end of a failing command is the part that says why.
		# A marker rather than a silent truncation — and the marker counts every
		# line ever dropped, not just this trim. Recomputing it from the list
		# length pinned it at "2 earlier lines" forever, because the marker is
		# itself in the list it was measuring.
		tail = [line for line in step.output if not line.startswith(_TRUNCATION_PREFIX)]
		step.dropped += len(tail) - (MAX_STEP_LINES - 1)
		step.output = [
			f"{_TRUNCATION_PREFIX}{step.dropped} earlier lines — the full output is below."
		] + tail[-(MAX_STEP_LINES - 1) :]

	def succeed(self, key: str | None = None, detail: str = "") -> None:
		self._close(key or self._current, SUCCESS, detail)

	def fail(self, key: str | None = None, detail: str = "") -> None:
		self._close(key or self._current, FAILURE, detail)

	def skip(self, key: str, detail: str = "") -> None:
		step = self.get(key)
		if step and step.status == PENDING:
			step.status = SKIPPED
			step.detail = detail

	def abandon(self, detail: str = "") -> None:
		"""Mark everything still waiting as skipped.

		Called when the job stops early. Without it the remaining steps sit in
		`Pending` forever, which reads as "still going" long after it stopped.
		"""
		# The reason goes on the step that FAILED, not on every step after it.
		# Repeating it made a five-step plan render the same sentence five
		# times, which in a log somebody is reading to find out what went wrong
		# is four lines of noise around the one that matters.
		for step in self.steps:
			if step.status == RUNNING:
				self._close(step.key, FAILURE, detail)
			elif step.status == PENDING:
				step.status = SKIPPED
				step.detail = "Did not run."

	# ------------------------------------------------------------------

	def _close(self, key: str | None, status: str, detail: str) -> None:
		step = self.get(key) if key else None
		if step is None or step.status in DONE:
			return
		step.status = status
		step.finished_at = self._stamp()
		if detail:
			step.detail = detail
		if step.started_at:
			try:
				started = datetime.fromisoformat(step.started_at)
				step.duration = round((self._now() - started).total_seconds(), 1)
			except ValueError:
				step.duration = None
		if self._current == key:
			self._current = None

	def _stamp(self) -> str:
		return self._now().isoformat(timespec="seconds")

	# ------------------------------------------------------------------

	def as_list(self) -> list[dict]:
		return [step.as_dict() for step in self.steps]

	def summary(self) -> str:
		"""One line: how far it got. Used as the fallback error summary."""
		failed = next((s for s in self.steps if s.status == FAILURE), None)
		if failed:
			return f"Failed at: {failed.title}"
		done = sum(1 for s in self.steps if s.status == SUCCESS)
		return f"{done} of {len(self.steps)} steps completed"


def make(*specs: tuple[str, str, str]) -> list[Step]:
	"""Build a plan from `(key, title, description)` triples."""
	return [Step(key=key, title=title, description=description) for key, title, description in specs]


# ----------------------------------------------------------------------
# The plans
# ----------------------------------------------------------------------

CHECK = ("check", "Check before starting", "Confirm the bench, the source and the options make sense.")
RESCAN = ("rescan", "Re-read the bench", "Refresh apps, sites and git state from disk.")


def for_clone(install_on_site: bool) -> list[Step]:
	specs = [
		CHECK,
		("access", "Verify repository access", "Ask GitHub for the branch before spending minutes on a clone."),
		("clone", "Clone the app", "bench get-app — the long one."),
	]
	if install_on_site:
		specs.append(("install", "Install on the site", "bench --site <site> install-app"))
	specs.append(RESCAN)
	return make(*specs)


def for_pull() -> list[Step]:
	return make(
		CHECK,
		("pull", "Fetch and merge", "git pull inside the app directory."),
		RESCAN,
	)


def for_command(label: str) -> list[Step]:
	return make(CHECK, ("run", label, "Run the command and stream its output."))


def for_provision(apps: list[str], with_site: bool, with_domain: bool) -> list[Step]:
	"""Building a bench, announced in full before anything is spent.

	One step per app rather than a single "install the apps": these are the
	slowest parts and the ones most likely to fail individually, and "failed
	while cloning erpnext" is a different problem from "failed while cloning
	the private one nobody has access to".
	"""
	specs = [
		("check", "Check before building", "Disk, memory, the interpreter, and that the name is free."),
		("init", "Create the bench", "bench init — clones frappe and builds the environment. The long one."),
		("ports", "Move it off the default ports", "So it does not share redis with an existing bench."),
	]
	for app in apps:
		specs.append((f"get:{app}", f"Fetch {app}", "bench get-app"))
	if with_site:
		specs.append(("site", "Create the site", "bench new-site — the database is created here."))
		for app in apps:
			specs.append((f"install:{app}", f"Install {app}", "bench --site <site> install-app"))
	if with_domain:
		specs.append(("domain", "Point the domain here", "Write the DNS record and tell frappe about it."))
	specs.append(RESCAN)
	return make(*specs)


def for_console(label: str) -> list[Step]:
	"""A console command: check, run, then re-read the bench.

	The rescan is here BECAUSE the command was arbitrary, not despite it. For a
	catalogue entry we know whether it can change the bench; for this one we
	know nothing — a `git checkout` in an app directory moves a branch, and the
	app list would keep showing the old one until somebody happened to rescan.
	Re-reading afterwards is the only way the bench view stays true.
	"""
	return make(
		("check", "Check before running", "Confirm the bench is usable and installs are allowed."),
		("run", label, "Run it in the bench directory and stream the output."),
		RESCAN,
	)


def for_ssl(mode: str, dry_run: bool) -> list[Step]:
	if mode == "issue":
		return make(
			CHECK,
			("issue", "Issue the certificate", "Stop nginx, run certbot, write the config, start nginx."),
		)
	return make(
		CHECK,
		(
			"renew",
			"Rehearse renewal" if dry_run else "Renew the certificates",
			"certbot renew, with nginx stopped for the check and started again afterwards.",
		),
	)


def for_restore(backup_first: bool) -> list[Step]:
	specs = [
		("check", "Check before restoring", "Backup on disk, credentials present, room on the disk."),
	]
	if backup_first:
		specs.append(
			("safety", "Back up the site first", "So there is a way back if this restore is the wrong one.")
		)
	specs += [
		("restore", "Restore the site", "bench restore — the database is dropped and reloaded."),
		RESCAN,
	]
	return make(*specs)
