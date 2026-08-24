<template>
	<AppShell title="Settings" subtitle="read-only summary" :monitoring="Boolean(settings.ssh_monitoring_enabled)">
		<template #actions>
			<Button :loading="ingesting" @click="ingestNow">
				<template #prefix><Icon name="play" :size="14" /></template>
				Ingest now
			</Button>
		</template>

		<div class="grid gap-3 lg:grid-cols-2">
			<section class="u-card overflow-hidden">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Monitoring</h2>
				</header>

				<div class="flex items-start justify-between gap-4 border-b border-[var(--rule)] px-4 py-3.5">
					<div class="min-w-0">
						<p class="text-[13px] font-medium">Collect SSH events</p>
						<p class="mt-0.5 text-[12px] leading-relaxed text-[var(--ink-faint)]">
							The master switch. While off, the scheduled reader exits immediately and
							nothing new is recorded.
						</p>
					</div>
					<button
						role="switch"
						:aria-checked="String(Boolean(settings.ssh_monitoring_enabled))"
						class="relative h-[22px] w-[38px] shrink-0 rounded-full border transition-colors duration-200"
						:class="settings.ssh_monitoring_enabled
							? 'border-[var(--ink)] bg-[var(--ink)]'
							: 'border-[var(--rule-strong)] bg-[var(--paper-sunk)]'"
						:disabled="toggling"
						@click="toggleMonitoring"
					>
						<span
							class="absolute top-[2px] h-[16px] w-[16px] rounded-full bg-[var(--paper)] shadow-sm transition-all duration-200 ease-[var(--ease)]"
							:class="settings.ssh_monitoring_enabled ? 'left-[18px]' : 'left-[2px]'"
							:style="!settings.ssh_monitoring_enabled ? { background: 'var(--ink-ghost)' } : null"
						/>
					</button>
				</div>

				<dl class="divide-y divide-[var(--rule)]">
					<Row label="Log source" :value="settings.detected_log_source || settings.log_source" />
					<Row label="Auth log path" :value="settings.auth_log_path" mono />
					<Row label="Geolocation" :value="settings.geo_enabled ? settings.geo_resolver : 'disabled'" />
					<Row label="Alerts" :value="settings.alerts_enabled ? `on, threshold ${settings.failed_login_threshold}` : 'off'" />
					<Row label="App installs" :value="settings.allow_app_install ? 'allowed' : 'blocked'" />
				</dl>
			</section>

			<section class="u-card overflow-hidden">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Ingestion</h2>
				</header>
				<div v-if="loading" class="flex flex-col gap-2 p-4">
					<Skeleton v-for="n in 3" :key="n" height="1.1rem" />
				</div>
				<div v-else-if="checkpoints.length" class="divide-y divide-[var(--rule)]">
					<div v-for="cp in checkpoints" :key="cp.source" class="px-4 py-3">
						<div class="flex items-center justify-between gap-3">
							<span class="u-mono text-[13px]">{{ cp.source }}</span>
							<OutcomeMark
								:outcome="['OK', 'No New Records'].includes(cp.last_run_status) ? 'Success' : 'Failure'"
								:label="cp.last_run_status"
							/>
						</div>
						<p class="u-num mt-1 text-[11.5px] text-[var(--ink-faint)]">
							{{ cp.records_inserted }} inserted · {{ cp.records_skipped }} duplicate ·
							{{ cp.records_unparsed }} unrecognised
						</p>
						<p v-if="cp.last_error" class="u-mono mt-1 break-all text-[11px] text-[var(--ink-soft)]">
							{{ cp.last_error }}
						</p>
					</div>
				</div>
				<EmptyState v-else title="Never run" icon="refresh"
				            hint="The reader has not completed a pass yet." />
			</section>

			<section class="u-card overflow-hidden lg:col-span-2">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Everything else</h2>
				</header>
				<p class="px-4 py-3.5 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
					The remaining settings — retention, alert recipients, trusted countries, bench
					paths and the SSH command used for git — live on the Desk form, where each field
					carries the explanation of what changing it does. A toggle in a dashboard has no
					room for that, and these are settings worth reading before touching.
					<a :href="deskUrl" class="ml-1 text-[var(--ink)] underline underline-offset-2">Open in Desk</a>
				</p>
			</section>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, h, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import Skeleton from "../components/Skeleton.vue";
import { healthResource, runIngestResource, setMonitoringResource, settingsResource } from "../api";

const deskUrl = "/app/server-settings";

const Row = (props) =>
	h("div", { class: "flex items-baseline justify-between gap-4 px-4 py-2.5" }, [
		h("dt", { class: "text-[12.5px] text-[var(--ink-faint)]" }, props.label),
		h("dd", { class: `text-[13px] text-right ${props.mono ? "u-mono" : ""}` }, props.value ?? "—"),
	]);
Row.props = ["label", "value", "mono"];

const settingsRes = settingsResource();
const healthRes = healthResource();
const toggling = ref(false);
const ingesting = ref(false);

const settings = computed(() => settingsRes.data || {});
const loading = computed(() => settingsRes.loading && !settingsRes.data);
const checkpoints = computed(() => healthRes.data?.checkpoints || []);

async function toggleMonitoring() {
	toggling.value = true;
	try {
		const next = !settings.value.ssh_monitoring_enabled;
		await setMonitoringResource().submit({ enabled: next });
		toast.success(next ? "Monitoring enabled" : "Monitoring paused");
		settingsRes.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not change the setting");
	} finally {
		toggling.value = false;
	}
}

async function ingestNow() {
	ingesting.value = true;
	try {
		const result = await runIngestResource().submit({});
		toast.success(
			result.error
				? `Ingest reported: ${result.error}`
				: `Read ${result.read ?? 0}, inserted ${result.inserted ?? 0}`,
		);
		healthRes.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Ingest failed");
	} finally {
		ingesting.value = false;
	}
}

onMounted(() => {
	settingsRes.fetch();
	healthRes.fetch();
});
</script>
