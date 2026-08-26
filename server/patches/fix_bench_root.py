# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Clear a Bench Root that points at a directory this machine does not have.

The DocType shipped with `default: "/home/patoo"` — the home directory of the
box it was written on. A default on a Data field is applied the first time the
Single is saved, so every install that had ever opened Settings had that path
written into it, and the bench scan then looked somewhere that did not exist
and reported, perfectly truthfully, that there were no benches. The server it
was installed on had twelve.

The default is gone. This clears what it already wrote, so `get_bench_root()`
falls back to the directory this bench actually sits in.

Deliberately narrow: it only clears a root that is NOT a directory on this
machine. An operator who set a real one keeps it.
"""

import os

import frappe


def execute():
	root = (frappe.db.get_single_value("Server Settings", "bench_root") or "").strip()
	if not root or os.path.isdir(root):
		return

	frappe.db.set_single_value("Server Settings", "bench_root", "")
	frappe.db.commit()
	print(f"server: cleared Bench Root {root!r} — no such directory here; using this bench's parent instead.")
