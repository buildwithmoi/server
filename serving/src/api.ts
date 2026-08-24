/**
 * Typed wrappers over the app's whitelisted endpoints.
 *
 * WHY NOT CALL frappe DIRECTLY FROM COMPONENTS. Every method name would then be
 * a string literal scattered across a dozen files, and renaming one on the
 * Python side would fail silently at runtime in whichever view nobody opened.
 * Collected here, the whole client/server contract is one file long and a
 * rename is one edit.
 */

import { createResource } from "frappe-ui";

const M = "server.api";

export type Outcome = "Success" | "Failure" | "Info";

export interface Totals {
	days: number;
	success: number;
	failure: number;
	info: number;
	total: number;
	attacking_ips: number;
	sudo_commands: number;
	sudo_denied: number;
}

export interface TimelinePoint {
	day: string;
	success: number;
	failure: number;
	info: number;
}

export interface CountryRow {
	country: string;
	total: number;
	success: number;
	failure: number;
}

export interface SourceRow {
	ip: string;
	attempts: number;
	successes: number;
	usernames: number;
	last_seen: string;
	country: string | null;
	city: string | null;
	isp: string | null;
	asn: string | null;
	geo_status: string | null;
}

export interface Checkpoint {
	source: string;
	last_run_at: string | null;
	last_run_status: string;
	records_inserted: number;
	records_skipped: number;
	records_unparsed: number;
	last_error: string | null;
}

export interface Health {
	monitoring_enabled: boolean;
	log_source: string | null;
	geo_enabled: boolean;
	pending_geolocation: number;
	checkpoints: Checkpoint[];
	fixture_rows: number;
}

export interface Overview {
	days: number;
	generated_at: string;
	totals: Totals;
	timeline: TimelinePoint[];
	by_country: CountryRow[];
	top_sources: SourceRow[];
	targeted_usernames: { username: string; attempts: number; invalid: number }[];
	recent_events: Record<string, unknown>[];
	recent_sudo: Record<string, unknown>[];
	health: Health;
}

/** The dashboard's single round trip. */
export function overviewResource(days = 7) {
	return createResource({
		url: `${M}.get_overview`,
		params: { days },
		cache: ["server-overview", days],
	});
}

export function authEventsResource() {
	return createResource({ url: `${M}.list_auth_events` });
}

export function sudoCommandsResource() {
	return createResource({ url: `${M}.list_sudo_commands` });
}

export function ipAddressesResource() {
	return createResource({ url: `${M}.list_ip_addresses` });
}

export function settingsResource() {
	return createResource({ url: `${M}.get_settings_summary` });
}

export function logSourceResource() {
	return createResource({ url: `${M}.check_log_source` });
}

/** What the reader has actually done — distinct from probing the machine. */
export function healthResource() {
	return createResource({ url: `${M}.get_health` });
}

/* ----------------------------------------------------------------- actions */

export function setMonitoringResource() {
	return createResource({ url: `${M}.set_monitoring_enabled` });
}

export function runIngestResource() {
	return createResource({ url: `${M}.run_ingest_now` });
}

export function resolveGeoResource() {
	return createResource({ url: `${M}.resolve_geolocation` });
}

export function replayFixtureResource() {
	return createResource({ url: `${M}.replay_fixture` });
}

export function purgeFixturesResource() {
	return createResource({ url: `${M}.purge_fixture_events` });
}
