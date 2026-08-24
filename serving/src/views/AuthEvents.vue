<template>
	<AppShell title="SSH Events" :subtitle="subtitle">
		<template #actions>
			<div class="relative">
				<Icon name="search" :size="14"
				      class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--ink-ghost)]" />
				<input
					v-model="search"
					type="search"
					placeholder="Search messages…"
					class="w-44 rounded-md border border-[var(--rule)] bg-[var(--paper)] py-1.5 pl-8 pr-2.5 text-[13px] outline-none transition-colors focus:border-[var(--ink)] sm:w-56"
					@input="debouncedReload"
				/>
			</div>
			<select v-model="outcome" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All outcomes</option>
				<option>Failure</option>
				<option>Success</option>
				<option>Info</option>
			</select>
		</template>

		<DataTable
			:columns="COLUMNS"
			:rows="rows"
			:loading="loading"
			:total="total"
			:start="start"
			:page-length="PAGE"
			empty-title="No matching events"
			empty-hint="Try widening the outcome filter, or clear the search."
			@page="reload"
		>
			<template #cell-outcome="{ row }">
				<OutcomeMark :outcome="row.outcome" :label="row.event_type" />
			</template>
			<template #cell-username="{ row }">
				<span class="u-mono">{{ row.username || "—" }}</span>
				<span v-if="row.invalid_user" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">(no such user)</span>
			</template>
			<template #cell-source_ip="{ row }">
				<span class="u-mono">{{ row.source_ip || "—" }}</span>
				<span v-if="row.country" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">{{ row.country }}</span>
			</template>
		</DataTable>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import { authEventsResource } from "../api";

const PAGE = 50;
const COLUMNS = [
	{ key: "event_time", label: "When", type: "datetime", width: "168px" },
	{ key: "outcome", label: "Event", width: "150px" },
	{ key: "username", label: "User", width: "170px" },
	{ key: "source_ip", label: "Source", width: "230px" },
	{ key: "auth_method", label: "Method", muted: true, width: "130px" },
	{ key: "raw_message", label: "Message", mono: true, muted: true },
];

const resource = authEventsResource();
const start = ref(0);
const outcome = ref("");
const search = ref("");

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const subtitle = computed(() => (loading.value ? "loading…" : `${total.value.toLocaleString()} recorded`));

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({
			start: nextStart,
			page_length: PAGE,
			outcome: outcome.value || null,
			search: search.value || null,
		})
		.catch((error) => toast.error(error.messages?.[0] || "Could not load events"));
}

// Typing in a search box should not fire a query per keystroke.
let timer;
function debouncedReload() {
	clearTimeout(timer);
	timer = setTimeout(() => reload(0), 280);
}

onMounted(() => reload(0));
</script>
