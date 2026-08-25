# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""auth.log tailing across rotation.

Rotation is where a naive tailer loses data, and it fails silently — you get a
gap in the audit log with nothing to say a gap happened. logrotate has two modes
and they break a byte-offset tailer in opposite directions:

  create        renames the file and makes a new one  -> inode changes,
                everything written before the rename is skipped
  copytruncate  copies then truncates in place        -> inode is the same but
                the file is now shorter, so the old offset points past the end

Tracking (inode, offset) together is what tells the two apart. These tests build
a real file on disk and rotate it both ways.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from server.ssh.authlog import AuthLogUnavailableError, read_lines

PREFIX = "2026-08-24T09:15:0"


def line(n: int) -> str:
	return f"{PREFIX}{n % 10}.000000+00:00 host sshd[40{n:02d}]: Accepted password for u{n} from 1.2.3.4 port 1 ssh2"


class AuthLogRotationTestCase(unittest.TestCase):
	def setUp(self):
		self._tmp = tempfile.TemporaryDirectory()
		self.dir = self._tmp.name
		self.path = os.path.join(self.dir, "auth.log")
		self.addCleanup(self._tmp.cleanup)

	def write(self, path: str, lines: list[str], mode: str = "a"):
		with open(path, mode, encoding="utf-8") as fh:
			for entry in lines:
				fh.write(entry + "\n")


class TestSequentialReads(AuthLogRotationTestCase):
	def test_reads_then_resumes_without_repeating(self):
		self.write(self.path, [line(1), line(2)], mode="w")
		first, inode, offset, sig = read_lines(self.path)
		self.assertEqual(first, [line(1), line(2)])

		self.write(self.path, [line(3)])
		second, inode2, offset2, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(second, [line(3)], "resumed read must not repeat earlier lines")
		self.assertEqual(inode2, inode)
		self.assertGreater(offset2, offset)

	def test_no_new_data_returns_nothing(self):
		self.write(self.path, [line(1)], mode="w")
		_, inode, offset, sig = read_lines(self.path)
		again, _, offset2, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(again, [])
		self.assertEqual(offset2, offset)

	def test_limit_is_respected_and_the_rest_is_not_lost(self):
		self.write(self.path, [line(i) for i in range(1, 11)], mode="w")
		batch, inode, offset, sig = read_lines(self.path, limit=4)
		self.assertEqual(len(batch), 4)
		rest, _, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig, limit=100)
		self.assertEqual(len(rest), 6, "the remainder must be readable on the next pass")


class TestPartialLine(AuthLogRotationTestCase):
	def test_half_written_line_is_not_consumed(self):
		"""rsyslog appends without locking, so the tail can be mid-write.

		Treating a partial line as consumed would advance the offset past it and
		lose the rest of that line forever once it is completed.
		"""
		self.write(self.path, [line(1)], mode="w")
		with open(self.path, "a", encoding="utf-8") as fh:
			fh.write("2026-08-24T09:15:09.000000+00:00 host sshd[4099]: Accepted pass")  # no newline

		batch, inode, offset, sig = read_lines(self.path)
		self.assertEqual(batch, [line(1)], "the partial line must not be returned")

		# Complete the line; the next read should return it whole.
		with open(self.path, "a", encoding="utf-8") as fh:
			fh.write("word for u99 from 1.2.3.4 port 1 ssh2\n")
		batch2, _, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(len(batch2), 1)
		self.assertTrue(batch2[0].endswith("ssh2"))
		self.assertIn("Accepted password for u99", batch2[0])


class TestRotationByRename(AuthLogRotationTestCase):
	"""logrotate's default: rename to .1 and create a fresh file."""

	def test_tail_of_the_rotated_file_is_not_lost(self):
		self.write(self.path, [line(1), line(2)], mode="w")
		_, inode, offset, sig = read_lines(self.path)

		# Written AFTER our read but BEFORE the rotation — the classic gap.
		self.write(self.path, [line(3)])
		os.rename(self.path, self.path + ".1")
		self.write(self.path, [line(4)], mode="w")

		batch, new_inode, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(
			batch,
			[line(3), line(4)],
			"must drain the rotated file's tail before reading the new one",
		)
		self.assertNotEqual(new_inode, inode, "the inode must be the new file's")

	def test_no_duplication_after_rotation(self):
		self.write(self.path, [line(1)], mode="w")
		_, inode, offset, sig = read_lines(self.path)
		os.rename(self.path, self.path + ".1")
		self.write(self.path, [line(2)], mode="w")

		batch, inode2, offset2, sig2 = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(batch, [line(2)])
		again, _, _, _ = read_lines(self.path, inode=inode2, offset=offset2, signature=sig2)
		self.assertEqual(again, [], "a second read must not re-deliver rotated lines")

	def test_missing_rotated_file_is_survivable(self):
		"""If .1 is gone (compressed to .1.gz), start the new file cleanly."""
		self.write(self.path, [line(1)], mode="w")
		_, inode, offset, sig = read_lines(self.path)
		os.remove(self.path)
		self.write(self.path, [line(2)], mode="w")

		batch, _, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(batch, [line(2)])


class TestInodeReuse(AuthLogRotationTestCase):
	"""The narrow case that (inode, offset) alone cannot see.

	A filesystem may hand the same inode straight back after a delete. If the
	replacement file has also grown past the old offset, both the inode check
	and the size check pass, and every line in the new file is skipped — a
	silent hole in the audit log, which is the one failure this app must not
	have.
	"""

	def test_same_inode_same_size_different_content_is_detected(self):
		self.write(self.path, [line(1)], mode="w")
		_, inode, offset, sig = read_lines(self.path)

		os.remove(self.path)
		self.write(self.path, [line(2)], mode="w")  # identical length by construction

		st = os.stat(self.path)
		if str(st.st_ino) != inode:
			self.skipTest("filesystem did not reuse the inode; nothing to prove here")

		self.assertEqual(st.st_size, offset, "precondition: the size check must also be fooled")
		batch, _, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(batch, [line(2)], "the head fingerprint must catch what inode and size miss")

	def test_signature_survives_appends(self):
		"""Appending must never look like rotation, or every read restarts at 0."""
		self.write(self.path, [line(1)], mode="w")
		_, inode, offset, sig = read_lines(self.path)
		self.write(self.path, [line(2), line(3)])

		batch, _, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(batch, [line(2), line(3)], "an append must not be mistaken for a new file")


class TestRotationByCopytruncate(AuthLogRotationTestCase):
	"""logrotate's copytruncate: same inode, file suddenly shorter."""

	def test_truncation_restarts_at_zero(self):
		self.write(self.path, [line(i) for i in range(1, 6)], mode="w")
		_, inode, offset, sig = read_lines(self.path)
		self.assertGreater(offset, 0)

		self.write(self.path, [line(9)], mode="w")  # truncate in place
		batch, inode2, _, _ = read_lines(self.path, inode=inode, offset=offset, signature=sig)
		self.assertEqual(batch, [line(9)], "a shorter file at the same inode means restart at 0")
		self.assertEqual(inode2, inode)


class TestMissingFile(AuthLogRotationTestCase):
	def test_unreadable_path_raises_a_typed_error(self):
		with self.assertRaises(AuthLogUnavailableError):
			read_lines(os.path.join(self.dir, "does-not-exist.log"))


if __name__ == "__main__":
	unittest.main()


class TestRotationDrainsCompletely(unittest.TestCase):
	"""A rotation is exactly when a busy log has the most left in it.

	The rotated file's new offset used to be discarded and the checkpoint moved
	to the fresh file at 0, so everything past the first `limit` lines of the
	rotated file was abandoned permanently — silently, with no gap anyone could
	see.
	"""

	def test_nothing_is_lost_when_the_rotation_exceeds_one_run(self):
		with tempfile.TemporaryDirectory() as root:
			live = os.path.join(root, "auth.log")
			with open(live, "w") as handle:
				handle.write("".join(f"line {i}\n" for i in range(100)))

			_, inode, offset, signature = read_lines(live, limit=30)

			os.rename(live, f"{live}.1")
			with open(live, "w") as handle:
				handle.write("".join(f"new {i}\n" for i in range(5)))

			seen = []
			for _ in range(10):
				batch, inode, offset, signature = read_lines(
					live, inode=inode, offset=offset, signature=signature, limit=30
				)
				if not batch:
					break
				seen.extend(batch)

			self.assertEqual(
				[l for l in seen if l.startswith("line ")],
				[f"line {i}" for i in range(30, 100)],
			)
			self.assertEqual([l for l in seen if l.startswith("new ")], [f"new {i}" for i in range(5)])

	def test_a_rotation_that_fits_in_one_run_still_moves_on(self):
		with tempfile.TemporaryDirectory() as root:
			live = os.path.join(root, "auth.log")
			with open(live, "w") as handle:
				handle.write("".join(f"line {i}\n" for i in range(10)))
			_, inode, offset, signature = read_lines(live, limit=5)

			os.rename(live, f"{live}.1")
			with open(live, "w") as handle:
				handle.write("new 0\n")

			seen = []
			for _ in range(5):
				batch, inode, offset, signature = read_lines(
					live, inode=inode, offset=offset, signature=signature, limit=100
				)
				if not batch:
					break
				seen.extend(batch)
			self.assertIn("new 0", seen)
			self.assertEqual(len([l for l in seen if l.startswith("line ")]), 5)
