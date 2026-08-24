<template>
	<div class="flex h-full bg-[var(--paper)] text-[var(--ink)]">
		<!-- ------------------------------------------------------- sidebar -->
		<aside
			class="fixed inset-y-0 left-0 z-40 flex w-[228px] shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] transition-transform duration-200 ease-[var(--ease)] lg:static lg:translate-x-0"
			:class="open ? 'translate-x-0' : '-translate-x-full'"
		>
			<div class="flex items-center gap-2.5 px-4 py-4">
				<span class="grid h-7 w-7 place-items-center rounded-[7px] bg-[var(--ink)] text-[var(--paper)]">
					<Icon name="shield" :size="15" stroke-width="2" />
				</span>
				<div class="min-w-0">
					<p class="u-display truncate text-[13.5px] leading-tight">Server</p>
					<p class="truncate text-[11px] leading-tight text-[var(--ink-faint)]">{{ siteName }}</p>
				</div>
			</div>

			<nav class="mt-1 flex flex-col gap-0.5 px-2" aria-label="Sections">
				<RouterLink
					v-for="item in nav"
					:key="item.name"
					:to="{ name: item.name }"
					class="group flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] transition-colors duration-150"
					:class="
						isActive(item.name)
							? 'bg-[var(--ink)] font-medium text-[var(--paper)]'
							: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)] hover:text-[var(--ink)]'
					"
					@click="open = false"
				>
					<Icon :name="item.icon" :size="16" />
					<span class="truncate">{{ item.label }}</span>
					<span
						v-if="item.count"
						class="u-num ml-auto text-[11px]"
						:class="isActive(item.name) ? 'text-[var(--paper)]/70' : 'text-[var(--ink-ghost)]'"
					>{{ item.count }}</span>
				</RouterLink>
			</nav>

			<div class="mt-auto border-t border-[var(--rule)] p-3">
				<!-- Ingest state lives in the chrome, not on one page: a monitoring
				     console that is quietly not ingesting looks exactly like a quiet
				     server, so this must be visible from everywhere. -->
				<div class="mb-2.5 flex items-center gap-2 px-1">
					<span
						class="h-1.5 w-1.5 shrink-0 rounded-full"
						:class="monitoring ? 'bg-[var(--ink)] u-live' : 'bg-[var(--ink-ghost)]'"
					/>
					<span class="text-[11px] text-[var(--ink-faint)]">
						{{ monitoring ? "Monitoring active" : "Monitoring off" }}
					</span>
				</div>
				<button
					class="flex w-full items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] text-[var(--ink-soft)] transition-colors duration-150 hover:bg-[var(--paper-sunk)] hover:text-[var(--ink)]"
					@click="$auth.logout()"
				>
					<Icon name="logout" :size="16" />
					<span class="truncate">Sign out</span>
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
	</div>
</template>

<script setup>
import { inject, ref } from "vue";
import { useRoute } from "vue-router";
import Icon from "./Icon.vue";

defineProps({
	title: { type: String, default: "" },
	subtitle: { type: String, default: "" },
	monitoring: { type: Boolean, default: false },
	siteName: { type: String, default: window.location.host },
});

const $auth = inject("$auth");
const route = useRoute();
const open = ref(false);

const nav = [
	{ name: "Dashboard", label: "Overview", icon: "gauge" },
	{ name: "AuthEvents", label: "SSH Events", icon: "shield" },
	{ name: "SudoCommands", label: "Sudo Commands", icon: "terminal" },
	{ name: "IpAddresses", label: "Addresses", icon: "globe" },
	{ name: "Settings", label: "Settings", icon: "sliders" },
];

const isActive = (name) => route.name === name;
</script>
