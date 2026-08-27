# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A POST-only endpoint has to be called with a POST.

Pressing "Check it now" did nothing at all: no toast, no error, a clean
console. `verify_domain_provider` declares `methods=["POST"]` — correctly, it
writes — and it was wired through frappe-ui's `createResource`, which issues a
GET. frappe answers 403, and the rejection never surfaced anywhere a person
could see it.

Measured over real HTTP against this site:

    GET  verify_domain_provider : 403
    POST verify_domain_provider : 200 {"message": {"ok": false, "error": ...}}

Which also explains a token showing "Never used" in the registrar's own portal
while somebody had pressed Verify repeatedly: the call never left the browser
as anything the server would accept.
"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest

APP = pathlib.Path(__file__).resolve().parents[1]
API_TS = APP.parent / "serving" / "src" / "api.ts"


def _post_only_endpoints() -> set[str]:
	source = (APP / "api.py").read_text()
	lines = source.splitlines()
	names = set()
	for node in ast.parse(source).body:
		if not isinstance(node, ast.FunctionDef):
			continue
		decorators = "\n".join(lines[d.lineno - 1] for d in node.decorator_list)
		if "whitelist" in decorators and 'methods=["POST"]' in decorators:
			names.add(node.name)
	return names


class EveryPostOnlyEndpointIsPosted(unittest.TestCase):
	def test_none_is_wired_through_a_get(self):
		text = API_TS.read_text()
		# `createResource` fixes the method at GET unless told otherwise, and
		# nothing here tells it otherwise.
		wired_by_get = set(re.findall(r"createResource\(\{\s*url: `\$\{M\}\.(\w+)`", text))
		offenders = sorted(wired_by_get & _post_only_endpoints())
		self.assertEqual(
			offenders,
			[],
			f"called with GET but declared POST-only: {offenders}",
		)

	def test_the_wrapper_posts(self):
		# `switchable` is what everything else uses, and it is the reason a
		# refusal is visible: it throws on a non-2xx instead of resolving.
		text = API_TS.read_text()
		wrapper = text[text.index("export function switchable") : text.index("function asError")]
		self.assertIn('method: "POST"', wrapper)
		self.assertIn("if (!response.ok) throw asError", wrapper)

	def test_what_still_uses_createresource_is_a_read(self):
		text = API_TS.read_text()
		remaining = set(re.findall(r"createResource\(\{\s*url: `\$\{M\}\.(\w+)`", text))
		self.assertTrue(
			remaining <= {"get_overview"},
			f"unexpected createResource calls: {sorted(remaining - {'get_overview'})}",
		)


if __name__ == "__main__":
	unittest.main()
