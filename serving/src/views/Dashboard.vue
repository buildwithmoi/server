<template>
	<AppShell
		title="Overview"
		:subtitle="subtitle"
		:monitoring="health.monitoring_enabled"
	>
		<template #actions>
			<div class="flex items-center overflow-hidden rounded-md border border-[var(--rule)]">
				<button
					v-for="option in RANGES"
					:key="option"
					class="px-2.5 py-1 text-[12px] transition-colors duration-150"
					:class="
						days === option
							? 'bg-[var(--ink)] font-medium text-[var(--paper)]'
							: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)]'
					"
					@click="setRange(option)"
				>{{ option }}d</button>
			</div>
			<Button :loading="overview.loading" @click="refresh">
				<template #prefix><Icon name="refresh" :size="14" /></template>
				Refresh
			</Button>
		</template>

		<!-- Ingestion health. Deliberately the first thing on the page: an empty
		     dashboard because nothing is being collected looks identical to an
		     empty dashboard because nothing is happening. -->
		<Transition
			enter-active-class="transition-all duration-300 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-1"
		>
			<div
				v-if="showBanner"
				class="mb-5 flex items-start gap-3 rounded-lg border border-[var(--ink)] bg-[var(--paper-sunk)] px-4 py-3"
			>
				<Icon name="alert" :size="17" class="mt-0.5 shrink-0" />
				<div class="min-w-0 flex-1">
					<p class="text-[13px] font-medium">{{ banner.title }}</p>
					<p class="mt-0.5 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">{{ banner.body }}</p>
				</div>
				<Button v-if="banner.action" :loading="acting" @click="banner.action.run">
					{{ banner.action.label }}
				</Button>
			</div>
		</Transition>

		<!-- headline numbers -->
		<div class="u-stagger grid grid-cols-2 gap-3 lg:grid-cols-4">
			<StatCard
				label="Failed logins" :value="totals.failure" :loading="loading"
				:hint="`from ${totals.attacking_ips} distinct address${totals.attacking_ips === 1 ? '' : 'es'}`"
			/>
			<StatCard label="Successful logins" :value="totals.success" :loading="loading"
			          :hint="`over the last ${days} days`" />
			<StatCard label="Sudo commands" :value="totals.sudo_commands" :loading="loading"
			          :hint="totals.sudo_denied ? `${totals.sudo_denied} denied or failed` : 'none denied'" />
			<StatCard label="Events recorded" :value="totals.total" :loading="loading"
			          :hint="health.fixture_rows ? `${health.fixture_rows.toLocaleString()} are replayed fixtures` : 'all from this machine'" />
		</div>

		<!-- activity -->
		<section class="u-card mt-3 px-4 py-4">
			<div class="mb-3 flex items-baseline justify-between gap-3">
				<h2 class="u-display text-[13.5px]">Daily activity</h2>
				<p class="text-[11.5px] text-[var(--ink-faint)]">last {{ days }} days</p>
			</div>
			<Skeleton v-if="loading" height="132px" />
			<BarTimeline v-else-if="timeline.length" :points="timeline" />
			<EmptyState v-else title="No activity in this window" icon="gauge" />
		</section>

		<div class="mt-3 grid gap-3 lg:grid-cols-2">
			<section class="u-card overflow-hidden">
				<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Where traffic comes from</h2>
					<RouterLink :to="{ name: 'IpAddresses' }"
					            class="text-[11.5px] text-[var(--ink-faint)] underline-offset-2 hover:underline">
						addresses
					</RouterLink>
				</header>
				<div v-if="loading" class="flex flex-col gap-2 p-3">
					<Skeleton v-for="n in 5" :key="n" height="1.1rem" />
				</div>
				<RankBars v-else-if="byCountry.length" :items="byCountry" label-key="country" value-key="total" />
				<EmptyState v-else title="No located traffic yet" icon="globe"
				            hint="Addresses are resolved to a country a few minutes after they are first seen." />
			</section>

			<section class="u-card overflow-hidden">
				<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Most persistent sources</h2>
					<span class="text-[11.5px] text-[var(--ink-faint)]">failed attempts</span>
				</header>
				<div v-if="loading" class="flex flex-col gap-2 p-3">
					<Skeleton v-for="n in 5" :key="n" height="1.1rem" />
				</div>
				<RankBars v-else-if="topSources.length" :items="topSources" label-key="ip"
				          value-key="attempts" note-key="country" mono />
				<EmptyState v-else title="No failed attempts" icon="shield"
				            hint="Nothing has been knocking on this server in the selected window." />
			</section>

			<section class="u-card overflow-hidden">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Accounts being guessed</h2>
				</header>
				<div v-if="loading" class="flex flex-col gap-2 p-3">
					<Skeleton v-for="n in 4" :key="n" height="1.1rem" />
				</div>
				<RankBars v-else-if="usernames.length" :items="usernames" label-key="username"
				          value-key="attempts" mono />
				<EmptyState v-else title="No username guessing" icon="terminal" />
			</section>

			<section class="u-card overflow-hidden">
				<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Latest events</h2>
					<RouterLink :to="{ name: 'AuthEvents' }"
					            class="text-[11.5px] text-[var(--ink-faint)] underline-offset-2 hover:underline">
						see all
					</RouterLink>
				</header>
				<div v-if="loading" class="flex flex-col gap-2 p-3">
					<Skeleton v-for="n in 6" :key="n" height="1.1rem" />
				</div>
				<ul v-else-if="recent.length" class="flex flex-col">
					<li
						v-for="event in recent"
						:key="event.name"
						class="flex items-center justify-between gap-3 border-b border-[var(--rule)] px-4 py-2 text-[13px] last:border-0"
					>
						<OutcomeMark :outcome="event.outcome" :label="event.event_type" />
						<span class="u-mono min-w-0 flex-1 truncate text-[var(--ink-soft)]">
							{{ event.username || "—" }}@{{ event.source_ip || "?" }}
						</span>
						<time class="u-num shrink-0 text-[11.5px] text-[var(--ink-faint)]">{{ ago(event.event_time) }}</time>
					</li>
				</ul>
				<EmptyState v-else title="No events recorded" icon="shield" />
			</section>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import BarTimeline from "../components/BarTimeline.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import RankBars from "../components/RankBars.vue";
import Skeleton from "../components/Skeleton.vue";
import StatCard from "../components/StatCard.vue";
import { overviewResource, replayFixtureResource, setMonitoringResource } from "../api";

const RANGES = [1, 7, 30];

const days = ref(7);
const acting = ref(false);
const overview = ref(overviewResource(days.value));

const data = computed(() => overview.value.data || {});
const loading = computed(() => overview.value.loading && !overview.value.data);
const totals = computed(() => data.value.totals || {});
const timeline = computed(() => data.value.timeline || []);
const byCountry = computed(() => data.value.by_country || []);
const topSources = computed(() => data.value.top_sources || []);
const usernames = computed(() => data.value.targeted_usernames || []);
const recent = computed(() => data.value.recent_events || []);
const health = computed(() => data.value.health || {});

const subtitle = computed(() => {
	if (loading.value) return "loading…";
	const at = data.value.generated_at;
	return at ? `updated ${ago(at)}` : "";
});

/**
 * One banner slot, highest-severity first.
 *
 * Stacking three notices would bury the one that matters; whichever problem is
 * most likely to make the whole page a lie is the one shown.
 */
const banner = computed(() => {
	const h = health.value;
	if (!h || loading.value) return {};

	if (!h.monitoring_enabled) {
		return {
			title: "Monitoring is switched off",
			body: "Nothing is being ingested, so this page reflects only what was already collected. Turn it on once you have confirmed this machine writes sshd records where the app can read them.",
			action: { label: "Turn on", run: enableMonitoring },
		};
	}
	const broken = (h.checkpoints || []).find(
		(c) => c.last_run_status && !["OK", "No New Records", "Never Run"].includes(c.last_run_status),
	);
	if (broken) {
		return {
			title: `Ingestion reported "${broken.last_run_status}"`,
			body: broken.last_error || `The ${broken.source} reader could not complete its last run.`,
		};
	}
	if (!totals.value.total) {
		return {
			title: "No events recorded yet",
			body: "Monitoring is on but nothing has arrived. On a machine with no sshd you can replay the bundled fixtures to see how the dashboard behaves.",
			action: { label: "Replay fixtures", run: replay },
		};
	}
	return {};
});

const showBanner = computed(() => Boolean(banner.value.title));

function setRange(value) {
	days.value = value;
	overview.value = overviewResource(value);
	overview.value.fetch();
}

function refresh() {
	overview.value.fetch();
	toast.success("Refreshed");
}

async function enableMonitoring() {
	acting.value = true;
	try {
		await setMonitoringResource().submit({ enabled: true });
		toast.success("Monitoring enabled");
		overview.value.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not enable monitoring");
	} finally {
		acting.value = false;
	}
}

async function replay() {
	acting.value = true;
	try {
		const result = await replayFixtureResource().submit({ days: 7 });
		toast.success(`Replayed ${result.inserted} events across ${result.days} days`);
		overview.value.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Replay failed (developer mode only)");
	} finally {
		acting.value = false;
	}
}

/** Compact relative time — "4m", "2h", "3d". */
function ago(value) {
	if (!value) return "";
	const then = new Date(String(value).replace(" ", "T"));
	if (Number.isNaN(then.getTime())) return "";
	const seconds = Math.max((Date.now() - then.getTime()) / 1000, 0);
	if (seconds < 60) return "just now";
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
	if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
	return `${Math.floor(seconds / 86400)}d ago`;
}

onMounted(() => overview.value.fetch());
</script>
