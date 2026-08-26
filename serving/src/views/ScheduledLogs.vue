<template>
	<AppShell title="Background work" :subtitle="subtitle">
		<template #actions>
			<label class="flex items-center gap-2 text-[12.5px]">
				<input v-model="failuresOnly" type="checkbox" @change="reload(0)" />
				<span>Failures only</span>
			</label>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			The detectors, the SSH ingest and the daily digest all run on the scheduler, with nobody
			watching. Two different things can go wrong and they look nothing alike: a run that threw
			leaves a traceback below, and a run that never happened at all leaves only a stale time
			in the panel above it.
		</p>

		<!-- The heartbeats come first deliberately. A job that stopped being
		     scheduled writes no failure row, so the list below would be empty
		     and reassuring at exactly the moment it should not be. -->
		<section v-if="detectors.length" class="mb-6">
			<h2 class="mb-2 text-[11px] font-medium uppercase tracking-wide text-[var(--ink-faint)]">
				Last heard from
			</h2>
			<div class="u-scroll max-h-[18rem] overflow-y-auto rounded-lg border border-[var(--rule)]">
				<table class="w-full text-[12.5px]">
					<tbody>
						<tr
							v-for="beat in detectors"
							:key="beat.source"
							class="border-b border-[var(--rule)] last:border-0"
						>
							<td class="py-2 pl-3 pr-2">
								<Icon
									:name="beat.last_status === 'OK' ? 'check' : 'alert'"
									:size="13"
									:class="beat.last_status === 'OK' ? 'u-ok' : 'u-danger'"
								/>
							</td>
							<td class="u-mono py-2 pr-3">{{ beat.source }}</td>
							<td class="py-2 pr-3 text-[var(--ink-faint)]">{{ when(beat.last_run) }}</td>
							<td class="py-2 pr-3 text-right text-[11.5px] text-[var(--ink-faint)]">
								<span :class="overdue(beat) ? 'u-danger' : ''">
									{{ overdue(beat) ? "overdue" : `every ${beat.expected_every}m` }}
								</span>
							</td>
							<td class="py-2 pr-3 text-[11.5px] text-[var(--ink-faint)]">run {{ beat.sequence }}</td>
						</tr>
					</tbody>
				</table>
			</div>
			<p
				v-for="beat in detectors.filter((b) => b.last_error)"
				:key="`e-${beat.source}`"
				class="mt-2 u-mono break-words text-[11.5px] u-danger"
			>
				{{ beat.source }}: {{ beat.last_error }}
			</p>
		</section>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 4" :key="n" class="h-12" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			:title="failuresOnly ? 'Nothing has failed' : 'Nothing recorded yet'"
			hint="A scheduled job that throws is recorded here with its traceback."
		/>

		<ul v-else class="u-scroll max-h-[calc(100vh-17rem)] space-y-2 overflow-y-auto pr-1">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] transition-colors hover:border-[var(--rule-strong)]"
			>
				<button type="button" class="flex w-full items-start gap-3 p-3 text-left" @click="toggle(row)">
					<Icon
						:name="row.status === 'Complete' ? 'check' : 'alert'"
						:size="14"
						class="mt-[3px] shrink-0"
						:class="row.status === 'Complete' ? 'u-ok' : 'u-danger'"
					/>
					<div class="min-w-0 flex-1">
						<p class="u-mono break-words text-[12.5px] leading-snug">{{ row.method }}</p>
						<p class="mt-1 break-words text-[11.5px] text-[var(--ink-faint)]">
							{{ when(row.creation) }} · {{ row.title }}
						</p>
					</div>
					<Icon
						v-if="row.details"
						name="chevron"
						:size="13"
						class="mt-1 shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
						:class="opened === row.name ? '-rotate-90' : 'rotate-90'"
					/>
				</button>

				<div v-if="opened === row.name && row.details" class="border-t border-[var(--rule)] p-3">
					<div class="mb-3 flex flex-wrap items-center gap-2">
						<Button variant="subtle" @click="copy(row)">
							<template #prefix><Icon name="copy" :size="13" /></template>
							{{ copied === row.name ? "Copied" : "Copy the traceback" }}
						</Button>
					</div>
					<pre class="u-term u-scroll max-h-[28rem] overflow-auto rounded-lg p-3 text-[12px] leading-[1.5]">{{ row.details }}</pre>
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
import { scheduledLogsResource } from "../api";

const PAGE = 50;

const resource = scheduledLogsResource();

const start = ref(0);
const failuresOnly = ref(true);
const opened = ref("");
const copied = ref("");

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const failing = computed(() => resource.data?.failing || 0);
const detectors = computed(() => resource.data?.detectors || []);
const loading = computed(() => resource.loading);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	return failing.value ? `${failing.value} failed` : "nothing failing";
});

function when(value) {
	if (!value) return "never";
	const date = new Date(value.replace(" ", "T"));
	return Number.isNaN(date.getTime())
		? value
		: date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Late by more than twice its own interval — one missed run is a busy worker. */
function overdue(beat) {
	if (!beat.last_run || !beat.expected_every) return false;
	const last = new Date(String(beat.last_run).replace(" ", "T")).getTime();
	if (Number.isNaN(last)) return false;
	return Date.now() - last > beat.expected_every * 60 * 1000 * 2;
}

function toggle(row) {
	copied.value = "";
	opened.value = opened.value === row.name ? "" : row.name;
}

async function copy(row) {
	const text = `${row.method}\n${row.creation}\n\n${row.details}`;
	try {
		await navigator.clipboard.writeText(text);
		copied.value = row.name;
		setTimeout(() => (copied.value = ""), 2000);
	} catch {
		toast.info("Copying was blocked — select the text instead.");
	}
}

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({ start: nextStart, page_length: PAGE, failures_only: failuresOnly.value ? 1 : 0 })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load the scheduled runs"));
}

onMounted(() => reload(0));
</script>
