<template>
	<div class="relative">
		<button
			class="flex w-full items-center gap-2.5 rounded-md py-[7px] text-[13px] transition-colors duration-150 hover:bg-[var(--paper-sunk)]"
			:class="[
				collapsed ? 'justify-center px-0' : 'px-2.5',
				unread ? 'u-danger font-medium' : 'text-[var(--ink-soft)] hover:text-[var(--ink)]',
			]"
			:title="collapsed ? label : undefined"
			@click="toggle"
		>
			<span class="relative shrink-0">
				<Icon name="alert" :size="16" />
				<!-- A dot, not just a number: the count is unreadable at 60px and
				     the whole point of the collapsed sidebar is that it still tells
				     you something is wrong. -->
				<span
					v-if="unread"
					class="u-live-dot absolute -right-1 -top-1 h-2 w-2 rounded-full"
					style="background: var(--danger)"
				/>
			</span>
			<span v-if="!collapsed" class="truncate">Alerts</span>
			<span
				v-if="!collapsed && unread"
				class="u-num ml-auto text-[11px]"
			>{{ unread }}</span>
		</button>

		<Transition
			enter-active-class="transition-all duration-150 ease-[var(--ease)]"
			enter-from-class="opacity-0 translate-y-1"
			leave-active-class="transition-all duration-100"
			leave-to-class="opacity-0"
		>
			<div
				v-if="open"
				ref="panel"
				class="absolute bottom-full z-40 mb-2 w-[340px] overflow-hidden rounded-lg border border-[var(--rule-strong)] bg-[var(--paper-raised)] shadow-[0_10px_30px_-12px_rgba(0,0,0,0.35)]"
				:class="collapsed ? 'left-0' : 'left-0'"
			>
				<header class="flex items-center justify-between gap-2 border-b border-[var(--rule)] px-3 py-2">
					<span class="u-item-label">Alerts</span>
					<button
						v-if="unread"
						class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
						@click="markAll"
					>Mark all read</button>
				</header>

				<div class="u-scroll max-h-[340px] overflow-y-auto">
					<button
						v-for="alert in alerts"
						:key="alert.name"
						class="block w-full border-b border-[var(--rule)] px-3 py-2.5 text-left transition-colors last:border-b-0 hover:bg-[var(--paper-sunk)]"
						:class="alert.read ? 'opacity-60' : ''"
						@click="openAlert(alert)"
					>
						<div class="flex items-start gap-2">
							<span
								class="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
								:style="{ background: alert.read ? 'var(--ink-ghost)' : 'var(--danger)' }"
							/>
							<span class="min-w-0 flex-1">
								<span class="u-item-label block">{{ alert.subject }}</span>
								<span class="u-item-detail mt-0.5 block line-clamp-2">
									{{ strip(alert.email_content) }}
								</span>
								<span class="u-item-detail mt-1 block text-[var(--ink-ghost)]">
									{{ when(alert.creation) }}
								</span>
							</span>
						</div>
					</button>

					<p v-if="!alerts.length" class="px-3 py-6 text-center">
						<span class="u-item-detail">
							Nothing to report. Intrusion patterns and disk pressure appear here.
						</span>
					</p>
				</div>
			</div>
		</Transition>
	</div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import Icon from "./Icon.vue";
import { alertsResource, markAlertsReadResource } from "../api";

/** Alerts are raised by the scheduler, so a slow poll is the right cadence. */
const POLL_MS = 60000;

defineProps({ collapsed: { type: Boolean, default: false } });

const resource = alertsResource();
const open = ref(false);
const panel = ref(null);
let timer = null;

const alerts = computed(() => resource.data?.alerts || []);
const unread = computed(() => resource.data?.unread || 0);
const label = computed(() => (unread.value ? `${unread.value} unread alerts` : "Alerts"));

function toggle() {
	open.value = !open.value;
	if (open.value) resource.fetch({ limit: 25 });
}

function strip(html) {
	// The bodies are written as HTML for the email; the panel wants the words.
	return String(html || "")
		.replace(/<[^>]+>/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function when(value) {
	const then = new Date(String(value).replace(" ", "T"));
	const mins = Math.round((Date.now() - then.getTime()) / 60000);
	if (mins < 2) return "just now";
	if (mins < 60) return `${mins} min ago`;
	if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
	return `${Math.round(mins / 1440)}d ago`;
}

async function openAlert(alert) {
	if (!alert.read) {
		await markAlertsReadResource().submit({ name: alert.name });
		alert.read = 1;
		if (resource.data) resource.data.unread = Math.max(0, resource.data.unread - 1);
	}
}

async function markAll() {
	await markAlertsReadResource().submit({});
	resource.fetch({ limit: 25 });
}

function onClickOutside(event) {
	if (open.value && !panel.value?.contains(event.target) && !event.target.closest("button")) {
		open.value = false;
	}
}

onMounted(() => {
	resource.fetch({ limit: 25 });
	timer = setInterval(() => resource.fetch({ limit: 25 }), POLL_MS);
	document.addEventListener("mousedown", onClickOutside);
});

onUnmounted(() => {
	if (timer) clearInterval(timer);
	document.removeEventListener("mousedown", onClickOutside);
});
</script>
