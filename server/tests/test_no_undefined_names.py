# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""No function reads a name that nothing in reach defines.

Written after a restore failed with `NameError: name 'remote' is not defined`,
in the first line of a pre-flight, on a server mid-migration. The line that
assigned it was removed while the block around it was being rewritten, and
nothing noticed: the module imports, the tests pass, and the failure only
appears when that branch actually runs — which, for a pre-flight, is the moment
somebody is restoring a production site.

This is the check `ruff`'s F821 does. It is duplicated here as a test because
lint is a thing somebody has to remember to run and a test is not.
"""

from __future__ import annotations

import ast
import builtins
import pathlib
import unittest

BUILTINS = set(dir(builtins))

#: Bound by the interpreter rather than by an assignment.
IMPLICIT = {"__file__", "__name__", "__doc__", "self", "cls"}


def _bound_by(node: ast.AST) -> set[str]:
	"""Every name this node introduces into scope."""
	names: set[str] = set()
	for child in ast.walk(node):
		if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
			names.add(child.id)
		elif isinstance(child, (ast.Import, ast.ImportFrom)):
			for alias in child.names:
				names.add(alias.asname or alias.name.split(".")[0])
		elif isinstance(child, ast.ExceptHandler) and child.name:
			names.add(child.name)
		elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
			names.add(child.name)
		elif isinstance(child, ast.arg):
			names.add(child.arg)
		elif isinstance(child, ast.Global) or isinstance(child, ast.Nonlocal):
			names.update(child.names)
		elif isinstance(child, ast.comprehension):
			for target in ast.walk(child.target):
				if isinstance(target, ast.Name):
					names.add(target.id)
	return names


def _undefined_in(path: pathlib.Path) -> list[str]:
	tree = ast.parse(path.read_text(), filename=str(path))
	module_scope = _bound_by(tree) | BUILTINS | IMPLICIT

	problems = []
	for node in ast.walk(tree):
		if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
			continue
		# Nested scopes see their parent's names; walking the whole function
		# body and collecting everything it binds is the conservative version
		# of that, and conservative is right — this must never cry wolf.
		in_scope = module_scope | _bound_by(node)
		for name in ast.walk(node):
			if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Load):
				if name.id not in in_scope:
					problems.append(f"{path.name}:{name.lineno} {node.name}() reads {name.id!r}")
	return problems


class NoUndefinedNames(unittest.TestCase):
	def test_every_module_in_this_app(self):
		root = pathlib.Path(__file__).resolve().parents[1]
		problems: list[str] = []
		for source in sorted(root.rglob("*.py")):
			if "__pycache__" in source.parts:
				continue
			problems.extend(_undefined_in(source))
		self.assertEqual(problems, [], "undefined names:\n  " + "\n  ".join(problems))


if __name__ == "__main__":
	unittest.main()
