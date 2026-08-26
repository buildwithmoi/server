<template>
	<AppShell title="Bench moves" :subtitle="subtitle">
		<template #actions>
			<Button variant="subtle" :loading="loading" @click="load">
				<template #prefix><Icon name="refresh" :size="13" /></template>
				Refresh
			</Button>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Every bench moved here from another server. A move that stopped halfway is not
			history — open it to see which step stopped and why, fix that one thing, and continue
			from there. Nothing already done is repeated.
		</p>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 3" :key="n" class="h-16" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			title="Nothing has been moved here"
			hint="Start one from Benches → Move a bench here."
			icon="layers"
		/>

		<ul v-else class="flex flex-col gap-2">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border bg-[var(--paper)] transition-colors"
				:class="needsSomebody(row) ? 'border-[var(--ink)]' : 'border-[var(--rule)]'"
			>
				<RouterLink :to="{ name: 'Migration', params: { name: row.name } }" class="block p-3">
					<div class="flex flex-wrap items-center gap-2.5">
						<Icon :name="markFor(row).icon" :size="14" :class="markFor(row).class" class="shrink-0" />
						<span class="u-mono text-[13px]">{{ row.source_bench }}</span>
						<span class="text-[var(--ink-faint)]">→</span>
						<span class="u-mono text-[13px]">{{ row.target_bench }}</span>
						<span class="text-[11.5px] text-[var(--ink-faint)]">from {{ row.source_server }}</span>

						<span class="ml-auto flex items-center gap-3 text-[11.5px]">
							<span :class="needsSomebody(row) ? 'u-danger' : 'text-[var(--ink-faint)]'">
								{{ row.status }}
							</span>
							<span class="u-num text-[var(--ink-faint)]">
								{{ row.done }}/{{ row.total }}
								<template v-if="row.failed">· {{ row.failed }} failed</template>
							</span>
						</span>
					</div>

					<!-- The reason it stopped, on the page you find it from. -->
					<p v-if="row.notes" class="mt-1.5 text-[12px] leading-relaxed text-[var(--ink-soft)]">
						{{ row.notes }}
					</p>

					<p class="mt-1.5 text-[11.5px] text-[var(--ink-faint)]">
						{{ row.owner }} · {{ when(row.creation) }}
						<span v-if="needsSomebody(row)" class="u-danger"> · open it to continue</span>
					</p>
				</RouterLink>
			</li>
		</ul>
	</AppShell>
</template>

<script setup>
import { computed, onMounted } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import { benchMigrationsResource } from "../api";

const resource = benchMigrationsResource();

const rows = computed(() => resource.data?.rows || []);
const unfinished = computed(() => resource.data?.unfinished || []);
const loading = computed(() => resource.loading);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	if (unfinished.value.length) {
		return `${unfinished.value.length} waiting to be continued`;
	}
	return rows.value.length ? `${rows.value.length} recorded` : "none yet";
});

/** Running or Paused: work in flight, not a record of work done. */
const needsSomebody = (row) => ["Running", "Paused"].includes(row.status);

function markFor(row) {
	if (row.status === "Success") return { icon: "check", class: "u-ok" };
	if (row.status === "Paused") return { icon: "alert", class: "u-danger" };
	if (row.status === "Running") return { icon: "refresh", class: "" };
	if (row.status === "Cancelled") return { icon: "close", class: "text-[var(--ink-faint)]" };
	return { icon: "alert", class: "u-danger" };
}

function when(value) {
	if (!value) return "";
	const date = new Date(String(value).replace(" ", "T"));
	return Number.isNaN(date.getTime())
		? value
		: date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function load() {
	resource.submit({}).catch((error) => toast.error(error.messages?.[0] || "Could not load the moves"));
}

onMounted(load);
</script>
