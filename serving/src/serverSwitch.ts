/**
 * Which server the console is currently showing.
 *
 * WHY THIS IS ITS OWN MODULE and not part of `state.ts`. `api.ts` has to read
 * it on every call to decide whether to go direct or through the proxy, and
 * `state.ts` imports `api.ts` for the settings resource. Putting the switch in
 * `state.ts` made the two import each other, which ES modules will sometimes
 * tolerate and sometimes resolve to `undefined` depending on which file the
 * bundler happens to evaluate first — a failure that appears only in the
 * production build.
 *
 * It depends on nothing, so nothing can cycle through it.
 *
 * WHY sessionStorage RATHER THAN localStorage. A switch should not survive
 * closing the tab. A console opened tomorrow always starts on the machine you
 * logged into, rather than silently continuing to act on a server you last
 * looked at a week ago.
 */

import { computed, ref } from "vue";

const KEY = "server:current";

function remembered(): string {
	try {
		return sessionStorage.getItem(KEY) || "";
	} catch {
		// Private windows and blocked site data both throw here.
		return "";
	}
}

const current = ref(remembered());

/** Empty means the machine you logged into. */
export const currentServer = computed(() => current.value);
export const isRemote = computed(() => Boolean(current.value));

export function switchToServer(name: string) {
	current.value = name || "";
	try {
		if (current.value) sessionStorage.setItem(KEY, current.value);
		else sessionStorage.removeItem(KEY);
	} catch {
		// Not being able to remember it is survivable — the switch still holds
		// for this page load.
	}
}
