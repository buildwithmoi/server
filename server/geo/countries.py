# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Mapping ISO-3166 alpha-2 codes onto frappe's own Country records.

Geolocation providers return a code ("GH"); frappe's Country doctype is named by
its full name ("Ghana") and stores the code lowercase. Something has to bridge
the two, and building that map from frappe's own `geo/country_info.json` means
no new dependency, no fixture of our own to maintain, and no drift from whatever
country list the framework ships.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache

import frappe


@lru_cache(maxsize=1)
def _code_to_name() -> dict[str, str]:
	"""Build {lowercase ISO-2 code: Country docname} from frappe's data file."""
	path = os.path.join(frappe.get_app_path("frappe"), "geo", "country_info.json")
	try:
		with open(path, encoding="utf-8") as fh:
			data = json.load(fh)
	except (OSError, ValueError):
		frappe.logger("server").error(f"could not read {path}", exc_info=True)
		return {}

	mapping = {}
	for country_name, info in data.items():
		code = (info or {}).get("code")
		if code:
			mapping[code.strip().lower()] = country_name
	return mapping


def clear_cache() -> None:
	"""Drop the cached map. Only needed if frappe's country list changes."""
	_code_to_name.cache_clear()


def country_from_code(code: str | None) -> str | None:
	"""Return the Country docname for an ISO-2 code, or None.

	Rules, in order:
	1. No code -> None.
	2. Not in frappe's country list -> None. A provider returning something
	   frappe has never heard of must not become a broken Link.
	3. In the list but the Country record was deleted from this site -> None,
	   for the same reason. The code itself is still stored on the IP record, so
	   nothing is lost by declining to link.
	"""
	if not code:
		return None
	name = _code_to_name().get(code.strip().lower())
	if not name:
		return None
	return name if frappe.db.exists("Country", name) else None
