<template>
	<AppShell title="Security" :subtitle="subtitle">
		<template #actions>
			<div class="relative">
				<Icon name="search" :size="14"
				      class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--ink-ghost)]" />
				<input
					v-model="search"
					type="search"
					placeholder="Search findings…"
					class="w-44 rounded-md border border-[var(--rule)] bg-[var(--paper)] py-1.5 pl-8 pr-2.5 text-[13px] outline-none transition-colors focus:border-[var(--ink)] sm:w-56"
					@input="debouncedReload"
				/>
			</div>
			<select v-model="severity" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All severities</option>
				<option>Critical</option>
				<option>High</option>
				<option>Medium</option>
				<option>Info</option>
			</select>
			<select v-model="category" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All detectors</option>
				<option v-for="c in categories" :key="c.category" :value="c.category">
					{{ c.category }} ({{ c.total }})
				</option>
			</select>
			<select v-model="status" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="New">Open</option>
				<option value="Acknowledged">Acknowledged</option>
				<option value="Suppressed">Suppressed</option>
				<option value="">Everything</option>
			</select>
		</template>

		<!-- The counts are the first thing anyone looks at, so they are the
		     first thing on the page, and clicking one filters to it. -->
		<div class="mb-4 flex flex-wrap gap-2">
			<button
				v-for="level in SEVERITIES"
				:key="level"
				type="button"
				class="flex items-center gap-2 rounded-lg border px-3 py-2 text-left transition-colors"
				:class="severity === level
					? 'border-[var(--ink)] bg-[var(--paper-sunk)]'
					: 'border-[var(--rule)] bg-[var(--paper)] hover:border-[var(--rule-strong)]'"
				@click="toggleSeverity(level)"
			>
				<SeverityMark :severity="level" :label="''" />
				<span class="text-[20px] font-medium tabular-nums leading-none">{{ open[level] || 0 }}</span>
				<span class="text-[12px] text-[var(--ink-faint)]">{{ level }}</span>
			</button>
		</div>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 6" :key="n" class="h-16" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			title="Nothing matching"
			:hint="status === 'New' && !severity && !category && !search
				? 'No open findings. The detectors are running; this is what a clean host looks like.'
				: 'Try widening the filters.'"
		/>

		<!--
			The list scrolls, not the page. Fifty rows each of which can expand
			meant the filters and the counts at the top were off-screen by the
			time you found the one you wanted, and scrolling back up to change a
			filter lost your place in the list.
		-->
		<ul v-else class="u-scroll max-h-[calc(100vh-19rem)] space-y-2 overflow-y-auto pr-1">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] transition-colors hover:border-[var(--rule-strong)]"
			>
				<button type="button" class="flex w-full items-start gap-3 p-3 text-left" @click="toggle(row.name)">
					<SeverityMark :severity="row.severity" :label="''" class="mt-[3px]" />
					<div class="min-w-0 flex-1">
						<p class="text-[13.5px] leading-snug">{{ row.subject }}</p>
						<p class="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11.5px] text-[var(--ink-faint)]">
							<span class="u-mono">{{ row.category }}</span>
							<span>{{ when(row.event_time) }}</span>
							<span v-if="row.occurrences > 1">seen {{ row.occurrences }}×</span>
							<span v-if="row.status !== 'New'" class="u-mono">{{ row.status.toLowerCase() }}</span>
							<!-- Delivery state matters: a finding that only
							     exists here is one an attacker can delete. -->
							<span v-if="!row.forwarded" class="text-[var(--warn)]">not forwarded</span>
						</p>
					</div>
					<Icon
						name="chevron"
						:size="13"
						class="mt-1 shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
						:class="expanded === row.name ? '-rotate-90' : 'rotate-90'"
					/>
				</button>

				<div v-if="expanded === row.name" class="border-t border-[var(--rule)] px-3 py-3">
					<p class="whitespace-pre-line text-[13px] leading-relaxed">{{ row.detail }}</p>

					<!-- The runbook is the reason the finding is worth raising.
					     An alert that says something is wrong and not what to do
					     about it gets acknowledged rather than acted on. -->
					<div v-if="row.runbook" class="mt-3 rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] p-3">
						<p class="mb-1 text-[11px] font-medium uppercase tracking-wide text-[var(--ink-faint)]">
							What to do
						</p>
						<p class="whitespace-pre-line text-[13px] leading-relaxed">{{ row.runbook }}</p>
					</div>

					<div v-if="row.status === 'New'" class="mt-3 flex flex-wrap items-center gap-2">
						<Button variant="subtle" :loading="acting === row.name" @click="acknowledge(row)">
							Acknowledge
						</Button>
						<Button variant="ghost" :loading="acting === row.name" @click="suppress(row, 24)">
							Silence for a day
						</Button>
						<Button variant="ghost" :loading="acting === row.name" @click="suppress(row, 24 * 7)">
							Silence for a week
						</Button>
						<!-- Deliberately no "silence forever". A suppression that
						     cannot expire is how a monitored system quietly stops
						     being monitored. -->
						<span class="text-[11.5px] text-[var(--ink-faint)]">Silences always expire.</span>
					</div>
					<p v-else-if="row.acknowledged_by" class="mt-3 text-[11.5px] text-[var(--ink-faint)]">
						Acknowledged by {{ row.acknowledged_by }} {{ when(row.acknowledged_at) }}.
					</p>
					<p v-if="row.suppressed_until" class="mt-2 text-[11.5px] text-[var(--ink-faint)]">
						Silent until {{ when(row.suppressed_until) }}.
						<span v-if="row.suppression_reason">{{ row.suppression_reason }}</span>
					</p>
				</div>
			</li>
		</ul>

		<div v-if="total > rows.length" class="mt-4 flex justify-center">
			<Button variant="subtle" :loading="loading" @click="reload(start + PAGE)">
				Show older findings
			</Button>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import SeverityMark from "../components/SeverityMark.vue";
import Skeleton from "../components/Skeleton.vue";
import { acknowledgeEventResource, securityEventsResource } from "../api";

const PAGE = 50;
const SEVERITIES = ["Critical", "High", "Medium", "Info"];

const resource = securityEventsResource();
const acknowledgeResource = acknowledgeEventResource();

const start = ref(0);
const severity = ref("");
const category = ref("");
const status = ref("New");
const search = ref("");
const expanded = ref("");
const acting = ref("");

const rows = computed(() => resource.data?.events || []);
const total = computed(() => resource.data?.total || 0);
const open = computed(() => resource.data?.open_by_severity || {});
const categories = computed(() => resource.data?.categories || []);
const loading = computed(() => resource.loading);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	const openTotal = SEVERITIES.reduce((sum, level) => sum + (open.value[level] || 0), 0);
	return openTotal ? `${openTotal} open` : "nothing open";
});

function when(value) {
	if (!value) return "";
	const date = new Date(value.replace(" ", "T"));
	if (Number.isNaN(date.getTime())) return value;
	const minutes = Math.round((Date.now() - date.getTime()) / 60000);
	if (minutes < 1) return "just now";
	if (minutes < 60) return `${minutes}m ago`;
	if (minutes < 60 * 24) return `${Math.round(minutes / 60)}h ago`;
	return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function toggle(name) {
	expanded.value = expanded.value === name ? "" : name;
}

function toggleSeverity(level) {
	severity.value = severity.value === level ? "" : level;
	reload(0);
}

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({
			start: nextStart,
			page_length: PAGE,
			severity: severity.value || null,
			category: category.value || null,
			status: status.value || null,
			search: search.value || null,
		})
		.catch((error) => toast.error(error.messages?.[0] || "Could not load findings"));
}

let timer;
function debouncedReload() {
	clearTimeout(timer);
	timer = setTimeout(() => reload(0), 280);
}

async function act(row, hours, reason) {
	acting.value = row.name;
	try {
		await acknowledgeResource.submit({ name: row.name, suppress_hours: hours, reason });
		toast.success(hours ? "Silenced" : "Acknowledged");
		reload(start.value);
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not update the finding");
	} finally {
		acting.value = "";
	}
}

const acknowledge = (row) => act(row, 0, "");
const suppress = (row, hours) => act(row, hours, `Silenced from the console for ${hours} hours`);

onMounted(() => reload(0));
</script>
