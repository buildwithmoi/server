<template>
	<div class="flex h-full bg-[var(--paper)] text-[var(--ink)]">
		<!-- ------------------------------------------------------- sidebar -->
		<aside
			class="fixed inset-y-0 left-0 z-40 flex shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] transition-all duration-200 ease-[var(--ease)] lg:static lg:translate-x-0"
			:class="[
				open ? 'translate-x-0' : '-translate-x-full',
				collapsed ? 'w-[60px]' : 'w-[228px]',
			]"
		>
			<div class="flex items-center gap-2.5 px-3.5 py-4" :class="collapsed ? 'justify-center px-0' : ''">
				<span class="grid h-7 w-7 shrink-0 place-items-center rounded-[7px] bg-[var(--ink)] text-[var(--paper)]">
					<Icon name="shield" :size="15" stroke-width="2" />
				</span>
				<div v-if="!collapsed" class="min-w-0">
					<p class="u-display truncate text-[13.5px] leading-tight">Server</p>
					<p class="truncate text-[11px] leading-tight text-[var(--ink-faint)]">{{ siteName }}</p>
				</div>
			</div>

			<nav class="mt-1 flex flex-col gap-0.5 px-2" aria-label="Sections">
				<RouterLink
					v-for="item in nav"
					:key="item.name"
					:to="{ name: item.name }"
					class="group relative flex items-center gap-2.5 rounded-md py-[7px] text-[13px] transition-colors duration-150"
					:title="collapsed ? item.label : undefined"
					:class="[
						isActive(item.name)
							? 'bg-[var(--ink)] font-medium text-[var(--paper)]'
							: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)] hover:text-[var(--ink)]',
						collapsed ? 'justify-center px-0' : 'px-2.5',
					]"
					@click="open = false"
				>
					<Icon :name="item.icon" :size="16" class="shrink-0" />
					<span v-if="!collapsed" class="truncate">{{ item.label }}</span>
					<!-- The beacon. Visible from every page, because the point of
					     backgrounding a clone is that you went somewhere else. -->
					<span
						v-if="item.name === 'Installs' && isRunning"
						class="u-live-dot h-2 w-2 shrink-0 rounded-full"
						:class="collapsed ? 'absolute right-1 top-1' : 'ml-auto'"
						:title="`${activeJobs.length} running`"
					/>
					<span
						v-else-if="item.count"
						class="u-num ml-auto text-[11px]"
						:class="isActive(item.name) ? 'text-[var(--paper)]/70' : 'text-[var(--ink-ghost)]'"
					>{{ item.count }}</span>
				</RouterLink>
			</nav>

			<div class="mt-auto border-t border-[var(--rule)] p-3" :class="collapsed ? 'px-2' : ''">
				<button
					class="mb-2 hidden w-full items-center gap-2.5 rounded-md py-[7px] text-[13px] text-[var(--ink-soft)] transition-colors duration-150 hover:bg-[var(--paper-sunk)] hover:text-[var(--ink)] lg:flex"
					:class="collapsed ? 'justify-center px-0' : 'px-2.5'"
					:title="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
					@click="toggleCollapsed"
				>
					<Icon name="panel" :size="16" class="shrink-0" :class="collapsed ? '' : 'rotate-180'" />
					<span v-if="!collapsed" class="truncate">Collapse</span>
				</button>

				<!-- Alerts live in the chrome for the same reason ingest state does.
				     Frappe delivers them to the desk at /app, which is not where
				     anyone using this app is looking — and an alert nobody sees is
				     the same as no alert, which was the original problem. -->
				<AlertsPanel :collapsed="collapsed" class="mb-2" />

				<!-- Ingest state lives in the chrome, not on one page: a monitoring
				     console that is quietly not ingesting looks exactly like a quiet
				     server, so this must be visible from everywhere. -->
				<div v-if="!collapsed" class="mb-2.5 flex items-center gap-2 px-1">
					<span
						class="h-1.5 w-1.5 shrink-0 rounded-full"
						:class="monitoringEnabled ? 'bg-[var(--ink)] u-live' : 'bg-[var(--ink-ghost)]'"
					/>
					<span class="text-[11px] text-[var(--ink-faint)]">
						{{ monitoringEnabled ? "Monitoring active" : "Monitoring off" }}
					</span>
				</div>
				<button
					class="flex w-full items-center gap-2.5 rounded-md py-[7px] text-[13px] text-[var(--ink-soft)] transition-colors duration-150 hover:bg-[var(--paper-sunk)] hover:text-[var(--ink)]"
					:class="collapsed ? 'justify-center px-0' : 'px-2.5'"
					:title="collapsed ? 'Sign out' : undefined"
					@click="$auth.logout()"
				>
					<Icon name="logout" :size="16" class="shrink-0" />
					<span v-if="!collapsed" class="truncate">Sign out</span>
				</button>
			</div>
		</aside>

		<!-- backdrop for the mobile drawer -->
		<Transition
			enter-active-class="transition-opacity duration-200"
			leave-active-class="transition-opacity duration-150"
			enter-from-class="opacity-0"
			leave-to-class="opacity-0"
		>
			<div v-if="open" class="fixed inset-0 z-30 bg-black/25 lg:hidden" @click="open = false" />
		</Transition>

		<!-- ---------------------------------------------------------- main -->
		<div class="flex min-w-0 flex-1 flex-col">
			<header
				class="sticky top-0 z-20 flex items-center gap-3 border-b border-[var(--rule)] bg-[var(--paper)]/85 px-4 py-3 backdrop-blur-sm sm:px-6"
			>
				<button
					class="-ml-1 rounded-md p-1.5 text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)] lg:hidden"
					aria-label="Open navigation"
					@click="open = true"
				>
					<Icon name="sliders" :size="18" />
				</button>

				<div class="min-w-0">
					<h1 class="u-display truncate text-[15px] leading-tight">{{ title }}</h1>
					<p v-if="subtitle" class="truncate text-[12px] leading-tight text-[var(--ink-faint)]">
						{{ subtitle }}
					</p>
				</div>

				<div class="ml-auto flex items-center gap-2">
					<slot name="actions" />
				</div>
			</header>

			<main class="u-scroll relative flex-1 overflow-y-auto px-4 py-5 sm:px-6">
				<slot />
			</main>
		</div>

		<!-- Teleports to <body>, so it floats above every page and survives
		     route changes without each view having to mount it. -->
		<JobDock />
	</div>
</template>

<script setup>
import { inject, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import Icon from "./Icon.vue";
import AlertsPanel from "./AlertsPanel.vue";
import JobDock from "./JobDock.vue";
import { activeJobs, adoptRunningJobs, isRunning } from "../jobs";
import { loadSettings, monitoringEnabled } from "../state";

defineProps({
	title: { type: String, default: "" },
	subtitle: { type: String, default: "" },
	siteName: { type: String, default: window.location.host },
});

const $auth = inject("$auth");
const route = useRoute();
const open = ref(false);

/**
 * Remembered per browser. A sidebar that springs back open on every navigation
 * is worse than one that does not collapse at all — and localStorage can throw
 * outright in a private window, so the read is guarded rather than assumed.
 */
const STORAGE_KEY = "server:sidebar-collapsed";
const collapsed = ref(false);
try {
	collapsed.value = localStorage.getItem(STORAGE_KEY) === "1";
} catch {
	collapsed.value = false;
}

function toggleCollapsed() {
	collapsed.value = !collapsed.value;
	try {
		localStorage.setItem(STORAGE_KEY, collapsed.value ? "1" : "0");
	} catch {
		// Preference simply is not remembered; the toggle still works.
	}
}

const nav = [
	{ name: "Dashboard", label: "Overview", icon: "gauge" },
	{ name: "Security", label: "Security", icon: "shield" },
	{ name: "Detectors", label: "Detectors", icon: "activity" },
	{ name: "Sessions", label: "SSH Sessions", icon: "users" },
	{ name: "AuthEvents", label: "SSH Events", icon: "terminal" },
	{ name: "SudoCommands", label: "Sudo Commands", icon: "terminal" },
	{ name: "IpAddresses", label: "Addresses", icon: "globe" },
	{ name: "Benches", label: "Benches", icon: "layers" },
	{ name: "Installs", label: "App Installs", icon: "download" },
	{ name: "GitHubProfiles", label: "GitHub Accounts", icon: "key" },
	{ name: "Settings", label: "Settings", icon: "sliders" },
];

const isActive = (name) => route.name === name;

// The chrome owns this, so every page shows the same truth without passing it.
onMounted(() => {
	loadSettings();
	// Pick up anything already running, so a page reload does not make an
	// in-flight clone look like it stopped.
	adoptRunningJobs();
});
</script>
