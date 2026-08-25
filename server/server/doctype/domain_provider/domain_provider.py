# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One registrar's API credential, and what it turned out to be able to reach.

Modelled on `GitHub Profile`, which solves the same problem: a secret the app
holds on the operator's behalf, plus the cached answer to "what does this
actually give us access to". Both questions matter — a token that authenticates
but holds none of the domains you meant is a specific and common mistake, and
it should be visible on the form rather than discovered halfway through a
provisioning run.

THE TOKEN IS NEVER RETURNED. `get_token` is the only reader, and the API layer
above exposes `has_token` rather than the value, the same way GitHub Profile
does. Clearing the column would leave the secret in `__Auth`; deletion goes
through `remove_encrypted_password`.
"""

import frappe
from frappe.model.document import Document


class DomainProvider(Document):
	def validate(self):
		self.provider_name = (self.provider_name or "").strip()
		self._enforce_single_default()

	def _enforce_single_default(self):
		"""Only one credential is the default; the newest choice wins.

		Silently demoting the previous one is kinder than refusing the save and
		sending somebody to go and clear the other first.
		"""
		if not self.is_default:
			return
		others = frappe.get_all(
			"Domain Provider", filters={"is_default": 1, "name": ("!=", self.name or "")}, pluck="name"
		)
		for other in others:
			frappe.db.set_value("Domain Provider", other, "is_default", 0, update_modified=False)

	def get_token(self) -> str | None:
		return self.get_password("api_token", raise_exception=False)

	def verify(self) -> dict:
		"""Ask the provider what this credential can reach, and record it.

		Records the failure as well as the success. A credential that stopped
		working — revoked, expired, scope removed — looks identical to a working
		one until something asks, and the point of storing the error is that the
		form can say so before a provisioning job depends on it.
		"""
		from server.domains import registry

		result = registry.dispatch(self.provider, self.get_token() or "", "list_zones")
		now = frappe.utils.now_datetime()

		if not result.ok:
			self.db_set(
				{"verify_error": result.error, "last_verified_at": now, "zone_count": 0},
				update_modified=False,
			)
			return {"ok": False, "error": result.error, "zones": []}

		self.set("zones", [])
		for zone in sorted(result.zones):
			self.append("zones", {"zone": zone, "status": "Manageable"})
		self.verify_error = ""
		self.last_verified_at = now
		self.zone_count = len(result.zones)
		self.flags.ignore_permissions = True
		self.save()

		return {"ok": True, "error": "", "zones": sorted(result.zones)}

	def zone_names(self) -> list[str]:
		return [row.zone for row in (self.zones or []) if row.zone]


def get_default_provider() -> str | None:
	"""The credential to pre-select, or the only one, or nothing."""
	chosen = frappe.get_all("Domain Provider", filters={"is_default": 1}, pluck="name", limit=1)
	if chosen:
		return chosen[0]
	only = frappe.get_all("Domain Provider", pluck="name", limit=2)
	return only[0] if len(only) == 1 else None
