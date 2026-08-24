# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Resumable read position for each log source.

WHY THIS IS NOT A FIELD ON `Server Settings`. This is machine state, rewritten
every five minutes by a background job; Server Settings is human configuration,
edited a handful of times ever. Mixing them puts a churning cursor into the
settings form's change log and invites an operator to "tidy up" a value the
ingester depends on. Keeping them apart also means adding a third source later
(fail2ban.log, say) is a new ROW, not a schema change.

WHY track_changes IS OFF. These rows are rewritten every five minutes by the
ingest job. Version tracking would append a Version document on every single
run — unbounded growth in `tabVersion` recording nothing a human will ever read.
It also walks straight into a frappe v16 bug: `frappe.locale.get_locale_value`
(frappe/locale.py:52) only binds `value` inside `if lang:`, so formatting a
Datetime for a version diff raises UnboundLocalError in any context where
`frappe.local.lang` is unset — which is exactly what a background worker is.
"""

import frappe
from frappe.model.document import Document

SOURCE_JOURNALD = "journald"
SOURCE_AUTHLOG = "authlog"

STATUS_NEVER_RUN = "Never Run"
STATUS_OK = "OK"
STATUS_NO_NEW = "No New Records"
STATUS_CURSOR_LOST = "Cursor Lost"
STATUS_UNAVAILABLE = "Source Unavailable"
STATUS_ERROR = "Error"


class ServerIngestCheckpoint(Document):
	def reset_position(self) -> None:
		"""Forget where we were, so the next run bootstraps from scratch.

		Used when a journal cursor is rejected. Safe by construction: every row
		carries a unique dedup hash, so re-reading a window inserts nothing that
		is already there.
		"""
		self.cursor = None
		self.byte_offset = 0
		self.inode = None
		self.file_signature = None

	def record_run(
		self,
		status: str,
		read: int = 0,
		inserted: int = 0,
		skipped: int = 0,
		unparsed: int = 0,
		error: str | None = None,
	) -> None:
		"""Persist the outcome of one ingest run.

		Deliberately writes with `db_set`/`ignore_permissions`: this runs in a
		worker with no session, and the row is machine-owned.
		"""
		self.last_run_at = frappe.utils.now_datetime()
		self.last_run_status = status
		self.records_read = read
		self.records_inserted = inserted
		self.records_skipped = skipped
		self.records_unparsed = unparsed
		self.last_error = (error or "")[:1000] or None
		self.save(ignore_permissions=True)


def get_checkpoint(source: str) -> ServerIngestCheckpoint:
	"""Fetch (or create) the checkpoint row for a source.

	Created on first use rather than seeded by a patch, so a source that is
	never used never leaves a confusing empty row behind.
	"""
	name = frappe.db.exists("Server Ingest Checkpoint", {"source": source})
	if name:
		return frappe.get_doc("Server Ingest Checkpoint", name)

	doc = frappe.get_doc(
		{
			"doctype": "Server Ingest Checkpoint",
			"source": source,
			"enabled": 1,
			"last_run_status": STATUS_NEVER_RUN,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc
