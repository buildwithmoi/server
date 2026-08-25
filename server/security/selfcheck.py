# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Has anything changed this app's own code, or its own findings?

Every detector in this package watches something else. This one watches the
watcher, because an intruder who understands what is installed here has a
cheaper option than evading the detectors: edit them. Two lines in
`rules.py` turn a Critical into an Info, and nothing else in the system
notices -- the scans still run, the heartbeat still climbs, the digest still
arrives, and it says everything is fine.

BE HONEST ABOUT WHAT THIS CAN AND CANNOT DO. An attacker who can edit
`rules.py` can also edit the recorded baseline, and one with database access
can rewrite the finding chain from end to end. Neither check is proof against
somebody who is careful, and a security feature that implies otherwise is
worse than one that admits its limits, because it gets trusted further than it
deserves.

What they do is raise the cost, and -- this is the part that matters -- they
produce something that can be checked from OUTSIDE. The chain head and the
code fingerprint are both published in the signed heartbeat and forwarded off
the box as they change. A rewritten history is then a history that disagrees
with the copies somebody else already holds, which is a question a person on
another machine can answer without trusting this one at all.

That is the whole design of this phase: not "you cannot tamper with this", but
"you cannot tamper with this WITHOUT the outside noticing".
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

#: Only what actually decides things. Tests, caches and build output change
#: constantly and mean nothing here; the Vue bundle is not what turns a
#: Critical into an Info.
WATCHED_SUFFIXES = (".py",)
SKIP_DIRECTORIES = frozenset({"__pycache__", "node_modules", ".git", "tests", "public", "serving"})


@dataclass(frozen=True)
class FileState:
	relative_path: str
	digest: str


@dataclass(frozen=True)
class CodeState:
	#: One hash over every watched file, which is what the heartbeat publishes.
	fingerprint: str
	files: tuple[FileState, ...]

	@property
	def count(self) -> int:
		return len(self.files)


def _hash_file(path: str) -> str:
	digest = hashlib.sha256()
	try:
		with open(path, "rb") as handle:
			for chunk in iter(lambda: handle.read(65536), b""):
				digest.update(chunk)
	except OSError:
		return ""
	return digest.hexdigest()


def scan_code(root: str) -> CodeState:
	"""Hash this app's own source, deterministically.

	Sorted before combining, so the fingerprint depends on the contents and
	not on the order the filesystem happened to return them in -- otherwise it
	would change between machines and mean nothing.
	"""
	files: list[FileState] = []

	for directory, dirnames, filenames in os.walk(root):
		dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRECTORIES)
		for filename in sorted(filenames):
			if not filename.endswith(WATCHED_SUFFIXES):
				continue
			full = os.path.join(directory, filename)
			files.append(FileState(os.path.relpath(full, root), _hash_file(full)))

	files.sort(key=lambda f: f.relative_path)
	combined = hashlib.sha256()
	for state in files:
		combined.update(f"{state.relative_path}:{state.digest}\n".encode())

	return CodeState(fingerprint=combined.hexdigest(), files=tuple(files))


def compare(previous: dict[str, str], current: CodeState) -> dict:
	"""What changed between two scans of the app's own code."""
	now = {state.relative_path: state.digest for state in current.files}
	return {
		"changed": sorted(p for p, d in now.items() if p in previous and previous[p] != d),
		"added": sorted(set(now) - set(previous)),
		"removed": sorted(set(previous) - set(now)),
	}
