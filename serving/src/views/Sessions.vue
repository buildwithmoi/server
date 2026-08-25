<template>
	<AppShell title="SSH Sessions" :subtitle="subtitle">
		<template #actions>
			<select v-model="status" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All sessions</option>
				<option value="Open">Open</option>
				<option value="Closed">Closed</option>
				<option value="Unknown">Unknown</option>
			</select>
		</template>

		<!--
			Status vocabulary is explained on the page rather than in a tooltip,
			because "Unknown" is the one people misread. A killed sshd, a host
			that lost power and a stalled ingest all look identical in the log,
			and none of them is the user logging out.
		-->
		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			A session is one SSH connection, built from the events sshd wrote about it.
			<b class="text-[var(--ink)]">Unknown</b> means it was opened, never seen closing, and is
			too old to still be running — not that the user logged out.
		</p>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 6" :key="n" class="h-14" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			title="No sessions recorded"
			hint="Sessions are built hourly from SSH events. If there are events but no sessions, the sessionizer has not run yet."
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
				<button type="button" class="flex w-full items-start gap-3 p-3 text-left" @click="toggle(row)">
					<span class="mt-[5px] h-[7px] w-[7px] shrink-0 rounded-full" :class="dot(row.status)" />
					<div class="min-w-0 flex-1">
						<p class="flex flex-wrap items-baseline gap-x-2 text-[13.5px]">
							<span class="u-mono">{{ row.username || "unknown user" }}</span>
							<span class="text-[var(--ink-faint)]">from</span>
							<span class="u-mono">{{ row.source_ip || "—" }}</span>
							<span v-if="row.country" class="text-[11.5px] text-[var(--ink-faint)]">{{ row.country }}</span>
						</p>
						<p class="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11.5px] text-[var(--ink-faint)]">
							<span>{{ when(row.login_time) }}</span>
							<span v-if="row.duration">for {{ duration(row.duration) }}</span>
							<span class="u-mono">{{ row.status.toLowerCase() }}</span>
							<span v-if="row.auth_method" class="u-mono">{{ row.auth_method }}</span>
						</p>
					</div>
					<div class="shrink-0 text-right">
						<p class="text-[13px] tabular-nums">{{ row.sudo_command_count || 0 }}</p>
						<p class="text-[11px] text-[var(--ink-faint)]">sudo</p>
					</div>
				</button>

				<div v-if="expanded === row.name" class="border-t border-[var(--rule)] px-3 py-3">
					<!--
						How the commands were tied to this session is shown with
						them, never inferred silently. An exact match on the PAM
						audit session id and a guess from username-and-time must
						not read the same, or the guess gets trusted like the
						measurement.
					-->
					<p v-if="row.attribution_method" class="mb-3 text-[11.5px] leading-relaxed" :class="attributionClass(row.attribution_method)">
						{{ attributionText(row.attribution_method) }}
					</p>

					<div v-if="detail.loading" class="space-y-1.5">
						<Skeleton v-for="n in 3" :key="n" class="h-8" />
					</div>

					<template v-else>
						<div v-if="commands.length">
							<p class="u-label mb-1.5">Commands run</p>
							<ul class="space-y-1">
								<li v-for="c in commands" :key="c.name" class="flex items-baseline gap-2 text-[12.5px]">
									<span class="shrink-0 text-[11px] tabular-nums text-[var(--ink-faint)]">{{ clock(c.event_time) }}</span>
									<span v-if="c.status !== 'Executed'" class="shrink-0 text-[11px] text-[var(--danger)]">{{ c.status }}</span>
									<span class="u-mono min-w-0 break-all">{{ c.command }}</span>
								</li>
							</ul>
						</div>
						<p v-else class="text-[12.5px] text-[var(--ink-faint)]">
							No sudo commands attributed to this session.
						</p>

						<div v-if="events.length" class="mt-3">
							<p class="u-label mb-1.5">What sshd wrote</p>
							<ul class="space-y-1">
								<li v-for="e in events" :key="e.name" class="flex items-baseline gap-2 text-[12px]">
									<span class="shrink-0 text-[11px] tabular-nums text-[var(--ink-faint)]">{{ clock(e.event_time) }}</span>
									<span class="u-mono min-w-0 break-all text-[var(--ink-faint)]">{{ e.raw_message || e.event_type }}</span>
								</li>
							</ul>
						</div>
					</template>
				</div>
			</li>
		</ul>

		<div v-if="total > rows.length" class="mt-4 flex justify-center">
			<Button variant="subtle" :loading="loading" @click="reload(start + PAGE)">Show older sessions</Button>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Skeleton from "../components/Skeleton.vue";
import { sshSessionDetailResource, sshSessionsResource } from "../api";

const PAGE = 50;

const resource = sshSessionsResource();
const detail = sshSessionDetailResource();

const start = ref(0);
const status = ref("");
const expanded = ref("");

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const commands = computed(() => detail.data?.commands || []);
const events = computed(() => detail.data?.events || []);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	return `${total.value.toLocaleString()} recorded`;
});

const DOTS = {
	Open: "bg-[var(--live)]",
	Closed: "bg-[var(--ink-ghost)]",
	Unknown: "bg-[var(--warn)]",
};
const dot = (s) => DOTS[s] || DOTS.Unknown;

const ATTRIBUTION = {
	"Audit Session": {
		text: "Commands are matched exactly — PAM stamped this login and these processes with the same session id.",
		class: "text-[var(--ink-faint)]",
	},
	"User and Time": {
		text: "Commands are inferred from the user and the time this session was open. Usually right, but not measured — this host's records carry no PAM audit session id.",
		class: "text-[var(--warn)]",
	},
	Ambiguous: {
		text: "This user had more than one session open when these commands ran, so nothing could be attributed to one of them.",
		class: "text-[var(--warn)]",
	},
	Unattributed: {
		text: "No commands could be tied to this session.",
		class: "text-[var(--ink-faint)]",
	},
};
const attributionText = (m) => ATTRIBUTION[m]?.text || "";
const attributionClass = (m) => ATTRIBUTION[m]?.class || "text-[var(--ink-faint)]";

function when(value) {
	if (!value) return "";
	const date = new Date(value.replace(" ", "T"));
	if (Number.isNaN(date.getTime())) return value;
	return date.toLocaleString(undefined, {
		month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
	});
}

function clock(value) {
	if (!value) return "";
	const date = new Date(value.replace(" ", "T"));
	return Number.isNaN(date.getTime())
		? ""
		: date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function duration(seconds) {
	if (!seconds) return "";
	if (seconds < 60) return `${seconds}s`;
	if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
	return `${(seconds / 3600).toFixed(1)}h`;
}

function toggle(row) {
	if (expanded.value === row.name) {
		expanded.value = "";
		return;
	}
	expanded.value = row.name;
	detail.submit({ name: row.name }).catch((error) => {
		toast.error(error.messages?.[0] || "Could not load the session");
	});
}

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({ start: nextStart, page_length: PAGE, status: status.value || null })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load sessions"));
}

onMounted(() => reload(0));
</script>
