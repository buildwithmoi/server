# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A frappe bench discovered on this machine.

Written entirely by `server.bench.discovery`; the only field a human owns is
`notes`. Rows are never deleted when a bench disappears — they are marked
inactive, so an install request that ran against one keeps a valid link.
"""

import os

import frappe
from frappe.model.document import Document

from server.bench import scanner


class ServerBench(Document):
	def path_exists(self) -> bool:
		return bool(self.bench_path) and scanner.is_bench_directory(self.bench_path)

	def assert_usable(self) -> None:
		"""Raise unless this bench is still a bench.

		Re-checked immediately before running any command against it: a scan can
		be hours old, and pointing `bench get-app` at a directory that is no
		longer a bench produces a confusing failure deep inside the CLI rather
		than a clear one here.
		"""
		if not self.bench_path:
			frappe.throw(f"{self.name} has no path recorded. Rescan benches first.")
		if not os.path.isdir(self.bench_path):
			frappe.throw(f"{self.bench_path} no longer exists. Rescan benches.")
		if not scanner.is_bench_directory(self.bench_path):
			missing = [
				marker
				for marker in scanner.BENCH_MARKERS
				if not os.path.isdir(os.path.join(self.bench_path, marker))
			]
			frappe.throw(
				f"{self.bench_path} is not a bench directory — missing {', '.join(missing)}.",
				title="Not A Bench",
			)

	def has_app(self, app_name: str) -> bool:
		return any(row.app_name == app_name for row in (self.apps or []))

	def site_names(self) -> list[str]:
		return [row.site_name for row in (self.sites or [])]
