# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The resolver interface every geolocation backend implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class ResolverSpec:
	"""What a resolver is and what it costs to use."""

	name: str
	label: str
	needs_network: bool
	max_batch: int
	description: str


@dataclass(frozen=True)
class GeoResult:
	"""What one address resolved to. `error` set means the lookup failed."""

	ip: str
	country_code: str | None = None
	country_name: str | None = None
	region: str | None = None
	city: str | None = None
	isp: str | None = None
	org: str | None = None
	asn: str | None = None
	latitude: float | None = None
	longitude: float | None = None
	error: str | None = None

	@property
	def ok(self) -> bool:
		return self.error is None and bool(self.country_code)


class GeoResolver(ABC):
	"""Resolve IP addresses to locations.

	WHY THE INTERFACE IS BATCH-FIRST. The obvious signature is
	`resolve(ip) -> GeoResult`, and it is the wrong one. ip-api.com's batch
	endpoint accepts 100 addresses and counts as a SINGLE request against its
	rate limit; a per-address interface would turn one request into a hundred
	and force a throttle to exist. Making `resolve_many` the primitive means the
	rate limit is respected by construction rather than by a sleep loop in a
	worker.

	An offline database backend (MaxMind GeoLite2) implements `resolve_many` as
	a trivial loop over local lookups, so the interface fits both shapes without
	either paying for the other's constraints.
	"""

	SPEC: ClassVar[ResolverSpec]

	@abstractmethod
	def resolve_many(self, ips: list[str]) -> dict[str, GeoResult]:
		"""Resolve up to `SPEC.max_batch` addresses. Never raises.

		A backend that cannot reach its provider returns a `GeoResult` carrying
		an `error` for each address, so one outage marks rows Failed and retries
		later rather than aborting the whole ingest pipeline.
		"""
