<template>
	<AppShell
		title="Overview"
		:subtitle="subtitle"
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

					<!-- The command that fixes it, verbatim and selectable. A
					     banner that describes a fix without giving the line to
					     run leaves the operator to reconstruct it. -->
					<div v-if="banner.command" class="mt-2 flex items-center gap-2">
						<code class="u-mono u-scroll min-w-0 flex-1 overflow-x-auto rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[12px]">{{ banner.command }}</code>
						<Button variant="ghost" @click="copyCommand(banner.command)">
							<template #prefix><Icon name="copy" :size="13" /></template>
							{{ copiedCommand ? "Copied" : "Copy" }}
						</Button>
					</div>
					<p v-if="banner.note" class="mt-1.5 text-[11.5px] text-[var(--ink-faint)]">{{ banner.note }}</p>
				</div>
				<Button v-if="banner.action" :loading="acting" @click="banner.action.run">
					{{ banner.action.label }}
				</Button>
			</div>
		</Transition>

		<!-- The machine itself. First, because a bench host that is out of disk
		     is a different kind of problem from anything else on this page and
		     the only one that takes every site down at once. -->
		<HealthPanel :data="systemHealth.data" />

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
				<div v-else-if="byCountry.length" class="u-scroll max-h-[19rem] overflow-y-auto">
					<RankBars :items="byCountry" label-key="country" value-key="total" />
				</div>
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
				<div v-else-if="topSources.length" class="u-scroll max-h-[19rem] overflow-y-auto">
					<RankBars :items="topSources" label-key="ip" value-key="attempts" note-key="country" mono />
				</div>
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
				<div v-else-if="usernames.length" class="u-scroll max-h-[19rem] overflow-y-auto">
					<RankBars :items="usernames" label-key="username" value-key="attempts" mono />
				</div>
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
				<ul v-else-if="recent.length" class="u-scroll flex max-h-[19rem] flex-col overflow-y-auto">
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
import { computed, onMounted, onUnmounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import HealthPanel from "../components/HealthPanel.vue";
import BarTimeline from "../components/BarTimeline.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import RankBars from "../components/RankBars.vue";
import Skeleton from "../components/Skeleton.vue";
import StatCard from "../components/StatCard.vue";
import { overviewResource, replayFixtureResource, runIngestResource, setMonitoringResource, systemHealthResource } from "../api";

const RANGES = [1, 7, 30];

/**
 * Refreshed on its own timer, not with the rest of the page.
 *
 * Disk and load change on the scale of seconds; the event counts behind them
 * are a 30-day aggregate and cost real query time. Tying the two together would
 * mean either a stale gauge or a needlessly expensive poll.
 */
const HEALTH_POLL_MS = 20000;
const systemHealth = systemHealthResource();
let healthTimer = null;

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
		const c = h.collection || {};

		// The cause that actually happened, and the one this banner used to
		// hide: the reader cannot open a single file. The install script says
		// so once, in a terminal; this page went on reporting zeros.
		if (!c.journal_readable && !c.auth_log_readable) {
			return {
				title: "Nothing can be read on this machine",
				body:
					`Neither the systemd journal nor ${c.auth_log_path || "the auth log"} is readable by ` +
					`${c.user || "the user this app runs as"}, so no SSH event can ever arrive. ` +
					`On Debian and Ubuntu the fix is to add that user to the 'adm' group.`,
				command: `sudo usermod -aG adm ${c.user || "$USER"}`,
				note: "Then restart the bench — group membership is only picked up by new processes.",
			};
		}

		// Nothing runs on its own while the scheduler is paused, and no other
		// page in this app would say so.
		if (c.scheduler_paused) {
			return {
				title: "The scheduler is paused",
				body: "The log reader runs every five minutes on the scheduler, and the scheduler is not running — so nothing will arrive on its own. Read once now, or start it.",
				command: "bench --site <site> enable-scheduler",
				action: { label: "Read now", run: readNow },
			};
		}

		const ran = (h.checkpoints || []).some((c2) => c2.last_run_status && c2.last_run_status !== "Never Run");
		if (!ran) {
			return {
				title: "Not read yet",
				body: `Monitoring is on and ${c.detected_source || "a source"} is readable (${c.explanation || ""}). The first read happens within five minutes, or do it now.`,
				action: { label: "Read now", run: readNow },
			};
		}

		return {
			title: "No events recorded yet",
			body: `The ${c.detected_source || "log"} reader ran and found nothing to record. On a quiet machine that is the correct answer — an SSH login will appear here within five minutes of happening.`,
			// Offered ONLY in developer mode. It is refused anywhere else, and
			// a button that refuses silently is worse than no button.
			action: c.developer_mode ? { label: "Replay fixtures", run: replay } : null,
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
	systemHealth.fetch();
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

const copiedCommand = ref(false);

async function copyCommand(text) {
	try {
		await navigator.clipboard.writeText(text);
		copiedCommand.value = true;
		setTimeout(() => (copiedCommand.value = false), 2000);
	} catch {
		toast.info("Copying was blocked — select the line instead.");
	}
}

/** Run the log reader immediately rather than waiting for the scheduler. */
async function readNow() {
	acting.value = true;
	try {
		const result = await runIngestResource().submit({});
		const inserted = result.inserted || 0;
		toast.success(inserted ? `Recorded ${inserted} events` : "Read the log; nothing new to record");
		systemHealth.fetch();
		overview.value.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not read the log");
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

onMounted(() => {
	overview.value.fetch();
	systemHealth.fetch();
	healthTimer = setInterval(() => systemHealth.fetch(), HEALTH_POLL_MS);
});

onUnmounted(() => healthTimer && clearInterval(healthTimer));
</script>
