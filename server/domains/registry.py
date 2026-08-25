# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Which DNS providers exist, and how to get one. Frappe-free.

`dispatch` is the only entry point anything outside this package should use.
It never raises: a provider that is misconfigured, unknown, or throwing from
somewhere this package did not anticipate comes back as a failed `Result` with
a sentence in it. The alternative is a provisioning job that has already cloned
four gigabytes dying on a typo'd token.
"""

from __future__ import annotations

from server.domains.base import DnsProvider, ProviderSpec, Result
from server.domains.godaddy import GoDaddyProvider
from server.domains.hostinger import HostingerProvider

PROVIDERS: dict[str, type[DnsProvider]] = {
	HostingerProvider.SPEC.name: HostingerProvider,
	GoDaddyProvider.SPEC.name: GoDaddyProvider,
}


def get_provider_specs() -> list[ProviderSpec]:
	"""Every provider, for the picker on the credentials form."""
	return [cls.SPEC for cls in PROVIDERS.values()]


def get_provider(name: str, token: str) -> DnsProvider | None:
	cls = PROVIDERS.get((name or "").strip())
	return cls(token) if cls else None


def dispatch(name: str, token: str, operation: str, **kwargs) -> Result:
	"""Call one operation on one provider, and never raise.

	The failure modes are all reported the same way because they all mean the
	same thing to the caller — this did not happen, here is why:

	  an unknown provider name (a doctype edited by hand, or a provider
	  removed from this app while a document still names it);
	  a missing token;
	  an operation this package does not have;
	  and anything the provider itself throws that its own error handling did
	  not already turn into a Result.
	"""
	if not (token or "").strip():
		return Result.failed(f"No credential is stored for {name or 'this provider'}.")

	provider = get_provider(name, token)
	if provider is None:
		known = ", ".join(sorted(PROVIDERS)) or "none"
		return Result.failed(f"{name!r} is not a DNS provider this app knows. Known: {known}.")

	handler = getattr(provider, operation, None)
	if not callable(handler):
		return Result.failed(f"{operation!r} is not something a DNS provider can do.")

	try:
		return handler(**kwargs)
	except Exception as exc:  # noqa: BLE001
		# The providers are written to return rather than raise, so reaching
		# here is a bug in one of them. It is still not a reason to take a
		# provisioning job down with it.
		return Result.failed(f"{name} failed unexpectedly: {type(exc).__name__}: {exc}")
