<template>
	<AppShell title="Crashes" :subtitle="subtitle">
		<template #actions>
			<label class="flex items-center gap-2 text-[12.5px]">
				<input v-model="mineOnly" type="checkbox" @change="reload(0)" />
				<span>This app only</span>
			</label>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Failures where something threw and nobody was catching — as opposed to a job that ran
			and reported itself. Open one for the whole traceback, then copy it out.
			<span v-if="mineOnly">
				Frappe records its own failures in the same place; untick to see those too.
			</span>
		</p>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 5" :key="n" class="h-12" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			title="Nothing has crashed"
			hint="Unhandled failures appear here with their full traceback."
		/>

		<ul v-else class="u-scroll max-h-[calc(100vh-17rem)] space-y-2 overflow-y-auto pr-1">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] transition-colors hover:border-[var(--rule-strong)]"
			>
				<button type="button" class="flex w-full items-start gap-3 p-3 text-left" @click="toggle(row)">
					<Icon name="alert" :size="14" class="mt-[3px] shrink-0 u-danger" />
					<div class="min-w-0 flex-1">
						<p class="u-mono break-words text-[12.5px] leading-snug">{{ row.title }}</p>
						<p class="mt-1 text-[11.5px] text-[var(--ink-faint)]">{{ when(row.creation) }}</p>
					</div>
					<Icon
						name="chevron"
						:size="13"
						class="mt-1 shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
						:class="opened === row.name ? '-rotate-90' : 'rotate-90'"
					/>
				</button>

				<div v-if="opened === row.name" class="border-t border-[var(--rule)] p-3">
					<div v-if="detail.loading" class="space-y-2">
						<Skeleton v-for="n in 3" :key="n" class="h-4" />
					</div>
					<template v-else-if="log">
						<div class="mb-3 flex flex-wrap items-center gap-2">
							<Button variant="subtle" @click="copy">
								<template #prefix><Icon name="copy" :size="13" /></template>
								{{ copied ? "Copied" : "Copy the traceback" }}
							</Button>
							<Button variant="ghost" @click="download">
								<template #prefix><Icon name="download" :size="13" /></template>
								Download
							</Button>
							<span class="text-[11.5px] text-[var(--ink-faint)]">{{ lineCount }} lines</span>
						</div>
						<pre class="u-term u-scroll max-h-[28rem] overflow-auto rounded-lg p-3 text-[12px] leading-[1.5]">{{ log.transcript }}</pre>
					</template>
				</div>
			</li>
		</ul>

		<div v-if="total > rows.length" class="mt-4 flex justify-center">
			<Button variant="subtle" :loading="loading" @click="reload(start + PAGE)">Show older</Button>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import { crashLogResource, crashLogsResource } from "../api";

const PAGE = 50;

const resource = crashLogsResource();
const detail = crashLogResource();

const start = ref(0);
const mineOnly = ref(true);
const opened = ref("");
const copied = ref(false);

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const log = computed(() => detail.data);
const lineCount = computed(() => (log.value?.transcript || "").split("\n").length);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	return total.value ? `${total.value} recorded` : "none";
});

function when(value) {
	if (!value) return "";
	const date = new Date(value.replace(" ", "T"));
	return Number.isNaN(date.getTime())
		? value
		: date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function toggle(row) {
	copied.value = false;
	if (opened.value === row.name) {
		opened.value = "";
		return;
	}
	opened.value = row.name;
	detail.submit({ name: row.name }).catch((error) => {
		toast.error(error.messages?.[0] || "Could not read that crash");
	});
}

async function copy() {
	try {
		await navigator.clipboard.writeText(log.value.transcript);
		copied.value = true;
		setTimeout(() => (copied.value = false), 2000);
	} catch {
		// Refused outside a secure context, which is where this app runs
		// before anyone has set up TLS. Downloading still achieves the goal.
		download();
		toast.info("Copying was blocked, so it downloaded instead.");
	}
}

function download() {
	const blob = new Blob([log.value.transcript], { type: "text/plain;charset=utf-8" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = log.value.filename;
	link.click();
	URL.revokeObjectURL(url);
}

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({ start: nextStart, page_length: PAGE, mine_only: mineOnly.value ? 1 : 0 })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load the crashes"));
}

onMounted(() => reload(0));
</script>
