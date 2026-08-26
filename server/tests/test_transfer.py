# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Deciding what to pull from another server, before pulling it.

Everything here is answerable without moving a byte, which is the point: the
alternative to checking first is finding out forty minutes into a
multi-gigabyte transfer that there was never room for it, or that the file
being written is not where anyone thought.
"""

import os
import tempfile
import unittest

from server.remote import transfer


def _backup(**parts):
	return {"parts": {k: {"name": v[0], "size": v[1]} for k, v in parts.items()}}


FULL = _backup(
	database=("20260826_000009-local_16_1-database.sql.gz", 11_030_381),
	public=("20260826_000009-local_16_1-files.tar", 4_096),
	private=("20260826_000009-local_16_1-private-files.tar", 10_240),
	config=("20260826_000009-local_16_1-site_config_backup.json", 343),
)


class TestWhatGetsPulled(unittest.TestCase):
	def test_the_database_comes_first(self):
		"""A transfer that is going to fail should fail before spending time
		on the files — and nothing can be restored without the dump."""
		self.assertEqual(transfer.plan(FULL, "/tmp")[0].part, "database")

	def test_files_can_be_left_behind(self):
		wanted = transfer.plan(FULL, "/tmp", want_public=False, want_private=False)
		self.assertEqual([w.part for w in wanted], ["database", "config"])

	def test_a_set_with_no_database_is_refused(self):
		with self.assertRaises(transfer.TransferRefused) as caught:
			transfer.plan(_backup(public=("f.tar", 10)), "/tmp")
		self.assertIn("nothing to restore", str(caught.exception))

	def test_the_source_filenames_are_kept(self):
		"""They carry the timestamp and the source site slug, which is what
		makes a pulled set recognisable next to locally-taken ones — and
		renaming would break the pattern that classifies a file at all."""
		wanted = transfer.plan(FULL, "/data/backups")
		self.assertEqual(
			wanted[0].destination, "/data/backups/20260826_000009-local_16_1-database.sql.gz"
		)


class TestAFilenameFromAnotherMachineIsNotTrusted(unittest.TestCase):
	"""It becomes a path on this disk, and it came from somewhere else."""

	def test_a_traversing_name_is_refused_not_trimmed(self):
		"""`basename` would have quietly turned this into `passwd` and carried
		on, which is a guess at what a hostile or broken source meant."""
		with self.assertRaises(transfer.TransferRefused) as caught:
			transfer.plan(_backup(database=("../../etc/passwd", 10)), "/tmp")
		self.assertIn("is a path, not a name", str(caught.exception))

	def test_an_absolute_name_is_refused(self):
		with self.assertRaises(transfer.TransferRefused):
			transfer.plan(_backup(database=("/etc/passwd", 10)), "/tmp")

	def test_a_nested_name_is_refused(self):
		with self.assertRaises(transfer.TransferRefused):
			transfer.plan(_backup(database=("sub/dir/db.sql.gz", 10)), "/tmp")

	def test_an_empty_name_is_refused(self):
		with self.assertRaises(transfer.TransferRefused):
			transfer.plan(_backup(database=("", 10)), "/tmp")

	def test_an_ordinary_name_is_accepted(self):
		self.assertEqual(len(transfer.plan(_backup(database=("db.sql.gz", 10)), "/tmp")), 1)


class TestRoom(unittest.TestCase):
	def test_it_refuses_a_pull_that_cannot_fit(self):
		huge = _backup(database=("db.sql.gz", 10 * 1024**4))
		with tempfile.TemporaryDirectory() as tmp:
			with self.assertRaises(transfer.TransferRefused) as caught:
				transfer.check_room(tmp, transfer.plan(huge, tmp))
		self.assertIn("free", str(caught.exception))

	def test_a_small_pull_is_allowed(self):
		with tempfile.TemporaryDirectory() as tmp:
			transfer.check_room(tmp, transfer.plan(_backup(database=("db.sql.gz", 1024)), tmp))

	def test_resuming_only_needs_room_for_what_is_missing(self):
		"""A half-finished transfer must not be refused for space it has
		already used — otherwise a large move can never be resumed."""
		with tempfile.TemporaryDirectory() as tmp:
			wanted = transfer.plan(_backup(database=("db.sql.gz", 5000)), tmp)
			with open(wanted[0].destination, "wb") as handle:
				handle.write(b"x" * 4000)
			self.assertEqual(transfer.already_here(wanted), 4000)
			transfer.check_room(tmp, wanted)


class TestReporting(unittest.TestCase):
	def test_sizes_read_as_sizes(self):
		wanted = transfer.plan(FULL, "/tmp")
		self.assertEqual(wanted[0].size_text, "10.5 MB")

	def test_describe_names_each_part(self):
		text = transfer.describe(transfer.plan(FULL, "/tmp"))
		for part in ("database", "public", "private", "config"):
			self.assertIn(part, text)

	def test_describing_nothing_does_not_produce_an_empty_line(self):
		self.assertEqual(transfer.describe([]), "nothing")
