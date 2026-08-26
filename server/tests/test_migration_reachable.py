# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A move that stopped halfway has to be findable again.

The detail page existed and nothing linked to it. Starting a move routed you
there once; close the tab and it was gone. So a migration paused at step one —
holding a bench, six apps and a site's worth of work — was unreachable, and the
only apparent way forward was to start the whole thing again and re-clone apps
that were already on disk.
"""

from __future__ import annotations

import pathlib
import unittest


def _src(*parts: str) -> str:
	return (pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / pathlib.Path(*parts)).read_text()


class ItIsReachable(unittest.TestCase):
	def test_there_is_a_list_route(self):
		router = _src("router", "index.js")
		self.assertIn('path: "/migrations",', router)
		self.assertIn('name: "Migrations"', router)

	def test_it_is_in_the_navigation(self):
		self.assertIn('{ name: "Migrations"', _src("components", "AppShell.vue"))

	def test_the_detail_page_links_back_to_the_list(self):
		self.assertIn("{ name: 'Migrations' }", _src("views", "Migration.vue"))

	def test_an_unfinished_move_is_surfaced_where_benches_are(self):
		# The page somebody actually opens when they think about benches.
		benches = _src("views", "Benches.vue")
		self.assertIn("unfinishedMove", benches)
		self.assertIn('"Running", "Paused"', benches)


class TheListSaysWhatIsWaiting(unittest.TestCase):
	def test_the_endpoint_reports_progress_and_what_needs_somebody(self):
		import inspect

		from server import api

		source = inspect.getsource(api.list_bench_migrations)
		for key in ('"total"', '"done"', '"failed"', '"unfinished"'):
			self.assertIn(key, source)

	def test_it_reconstructs_states_for_a_move_started_before_they_existed(self):
		import inspect

		from server import api

		source = inspect.getsource(api.list_bench_migrations)
		self.assertIn("if len(states) != len(actions):", source)


if __name__ == "__main__":
	unittest.main()
