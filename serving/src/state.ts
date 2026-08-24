/**
 * Shared app state.
 *
 * WHY THIS EXISTS. The sidebar shows whether ingestion is running, and it is
 * visible from every page — so it cannot be a prop that each view remembers to
 * pass. It was, and the result was that the indicator read "Monitoring off" on
 * every page that had no reason to know about monitoring, which is worse than
 * showing nothing: a security console that says collection is stopped when it
 * is running teaches you to ignore the one indicator that matters.
 *
 * One resource, fetched once, read directly by the chrome.
 */

import { computed, ref } from "vue";
import { settingsResource } from "./api";

const resource = settingsResource();
const loaded = ref(false);

export const settings = computed(() => resource.data || {});
export const monitoringEnabled = computed(() => Boolean(resource.data?.ssh_monitoring_enabled));
export const installsAllowed = computed(() => Boolean(resource.data?.allow_app_install));

/** Fetch once per page load; call with force after changing a setting. */
export function loadSettings(force = false) {
	if (loaded.value && !force) return Promise.resolve(resource.data);
	loaded.value = true;
	return resource.fetch();
}
