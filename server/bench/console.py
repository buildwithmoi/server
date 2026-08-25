# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Running an arbitrary command in a bench directory, deliberately and loudly.

WHY THIS EXISTS ALONGSIDE `commands.py`, WHICH REFUSES TO DO EXACTLY THIS.
The catalogue is the right default: thirty-seven entries, each assembled from a
fixed argv plus pattern-matched parameters, so nothing a browser sends becomes
an argument of git's or bench's own choosing. It covers the operations anyone
does repeatedly. It cannot cover the one-off — a `ls -la` to see why a path
looks wrong, a `git status` in an app directory, a `tail` of a file the log
reader does not know about — and the answer to those today is to leave the app
and open an SSH session, which is strictly worse: nothing records it.

So this is not a hole in the catalogue's design, it is the other half of it.
The catalogue is what you use; this is what you reach for when the catalogue
does not have it, and unlike an SSH session it leaves a trail.

WHY THERE IS NO BLOCKLIST. Refusing `rm -rf /` while allowing `dd`, `mv` or a
shell one-liner that does the same thing is theatre — it would suggest a safety
that does not exist, which is more dangerous than admitting there is none. What
makes this acceptable is not a filter, it is that the feature is loud:

  * the app-wide `allow_app_install` kill switch gates it, like every other
    subprocess this app spawns;
  * every command becomes a `Security Event`, so it is hash-chained, forwarded
    off the box as it is written, and appears in the daily digest;
  * the command and its whole output are stored on the request row.

WHY `stdin` STAYS CLOSED, and why that is a feature rather than a limitation.
Every job in this app runs with `stdin=DEVNULL`. Keeping that here is what
makes a non-interactive console honest: `vim`, `top`, `mariadb` and
`bench console` fail in the first second instead of hanging a worker for the
full timeout waiting on a prompt nobody can answer. The dialog says so plainly
rather than letting the operator discover it with a stuck job.

WHY `bash -lc` AND NOT A SPLIT ARGV. `shlex.split` would give a bare argv with
no pipes, no `&&`, no redirection and no globbing — which is most of the reason
to want a shell at all. Handing the string to bash restores those. Note what
this is NOT: `subprocess` still receives a three-element LIST and never
`shell=True`, so Python performs no interpolation of its own. Bash interprets
the string because that is the entire point; Python does not, because that
would be a second, invisible layer of the same thing.

Frappe-free, like the rest of `bench/`, so the refusals unit-test with no site
and no database.
"""

from __future__ import annotations

#: Long enough for a real one-liner with a pipeline; short enough that nobody
#: pastes a script into a text box that was never meant to hold one.
MAX_COMMAND = 4000

#: Fifteen minutes. A console command that has not finished by then is either
#: hung on something or is a job that should have been a catalogue entry.
DEFAULT_TIMEOUT = 900

#: `-l` makes it a login shell, so the operator gets the same PATH and
#: environment they would get over SSH. Without it, `bench` itself is often not
#: on PATH under a worker, and the first command anyone tries fails in a way
#: that looks like the feature is broken.
SHELL = "/bin/bash"
SHELL_FLAGS = "-lc"


class Refusal(Exception):
	"""The command will not be run, with a reason worth showing the operator."""


def validate(command: str | None) -> str:
	"""Return the command to run, or refuse with something actionable.

	Deliberately thin. The only things refused here are the ones that are not a
	command at all — everything else is the operator's decision, and pretending
	otherwise is the theatre this module's docstring argues against.
	"""
	text = (command or "").strip()

	if not text:
		raise Refusal("Type a command to run.")

	if len(text) > MAX_COMMAND:
		raise Refusal(
			f"That is {len(text)} characters, and the limit is {MAX_COMMAND}. "
			"A command this long is really a script — put it in a file and run the file."
		)

	# A NUL cannot survive the trip to execve and would truncate the command
	# silently at the point it appears, running a prefix of what was typed.
	# Silently running something OTHER than what was asked for is the one
	# failure this module must never have.
	if "\x00" in text:
		raise Refusal("That command contains a null byte, which cannot be passed to a shell.")

	return text


def build_argv(command: str) -> list[str]:
	"""The argv for a validated command.

	Three elements, always. The command is the last one and is passed through
	untouched — quoting, pipes and `&&` are bash's business, and rewriting any
	of it here would mean running something the operator did not type.
	"""
	return [SHELL, SHELL_FLAGS, command]


def summarise(command: str, limit: int = 60) -> str:
	"""A short label for a job list, from the head of the command.

	Whitespace is collapsed first so a command typed across several lines does
	not become a job titled with a newline in the middle of it.
	"""
	flat = " ".join((command or "").split())
	if len(flat) <= limit:
		return flat
	return flat[: limit - 1].rstrip() + "…"
