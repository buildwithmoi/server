<template>
	<AppShell title="Settings" :subtitle="subtitle">
		<template #actions>
			<Button v-if="dirtyCount" variant="ghost" @click="reset">Discard</Button>
			<Button v-if="dirtyCount" variant="solid" :loading="saving" @click="save">
				Save {{ dirtyCount }} change{{ dirtyCount === 1 ? "" : "s" }}
			</Button>
			<Button v-else :loading="ingesting" @click="ingestNow">
				<template #prefix><Icon name="play" :size="14" /></template>
				Read the log now
			</Button>
		</template>

		<div v-if="loading" class="grid gap-4 sm:grid-cols-[13rem_1fr]">
			<Skeleton class="h-56" />
			<Skeleton class="h-56" />
		</div>

		<div v-else class="grid gap-5 sm:grid-cols-[13rem_1fr]">
			<!--
				Tabs down the side rather than one long scroll. These are five
				unrelated subjects — a log reader, a geolocation service, an
				alert policy, a bench runner and eight security detectors — and
				a single column made finding any of them a hunt.
			-->
			<nav class="flex gap-1 overflow-x-auto sm:flex-col sm:overflow-visible">
				<button
					v-for="group in groups"
					:key="group.key"
					type="button"
					class="flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-left text-[13px] transition-colors"
					:class="group.key === active
						? 'bg-[var(--ink)] text-[var(--paper)]'
						: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)]'"
					@click="active = group.key"
				>
					<span class="truncate">{{ group.label }}</span>
					<span
						v-if="changedIn(group)"
						class="ml-auto h-1.5 w-1.5 shrink-0 rounded-full"
						:class="group.key === active ? 'bg-[var(--paper)]' : 'bg-[var(--ink)]'"
					/>
				</button>

				<button
					type="button"
					class="flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-left text-[13px] transition-colors"
					:class="active === 'status'
						? 'bg-[var(--ink)] text-[var(--paper)]'
						: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)]'"
					@click="active = 'status'"
				>
					Ingestion status
				</button>
			</nav>

			<section v-if="active === 'status'" class="u-card overflow-hidden">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">Ingestion</h2>
				</header>
				<div v-if="checkpoints.length" class="divide-y divide-[var(--rule)]">
					<div v-for="cp in checkpoints" :key="cp.source" class="px-4 py-3">
						<div class="flex flex-wrap items-center justify-between gap-3">
							<span class="u-mono text-[12.5px]">{{ cp.source }}</span>
							<span class="text-[12px]" :class="cp.last_run_status === 'OK' ? 'u-ok' : 'text-[var(--ink-faint)]'">
								{{ cp.last_run_status || "never run" }}
							</span>
						</div>
						<p class="mt-1 text-[11.5px] text-[var(--ink-faint)]">
							{{ cp.last_run_at || "no run recorded" }} ·
							{{ cp.records_inserted ?? 0 }} recorded, {{ cp.records_skipped ?? 0 }} already held
						</p>
						<p v-if="cp.last_error" class="u-mono mt-1 break-words text-[11.5px] u-danger">
							{{ cp.last_error }}
						</p>
					</div>
				</div>
				<EmptyState v-else title="Nothing has run yet" hint="The log reader runs every five minutes." />
			</section>

			<section v-else class="u-card overflow-hidden">
				<header class="border-b border-[var(--rule)] px-4 py-3">
					<h2 class="u-display text-[13.5px]">{{ activeGroup?.label }}</h2>
				</header>

				<div class="divide-y divide-[var(--rule)]">
					<div
						v-for="field in activeGroup?.fields || []"
						:key="field.fieldname"
						class="flex flex-wrap items-start gap-3 px-4 py-3.5"
					>
						<div class="min-w-0 flex-1">
							<div class="flex items-center gap-1.5">
								<span class="text-[13px] font-medium">{{ field.label }}</span>

								<!--
									The description on demand, not in the layout.
									These run to four and five sentences apiece —
									they are worth reading before changing a
									setting and ruinous to read past forty times
									looking for one.
								-->
								<span
									v-if="field.description"
									class="relative inline-flex"
									@mouseenter="hovered = field.fieldname"
									@mouseleave="hovered = ''"
								>
									<button
										type="button"
										class="flex h-[15px] w-[15px] items-center justify-center rounded-full border border-[var(--rule-strong)] text-[10px] leading-none text-[var(--ink-faint)] hover:border-[var(--ink)] hover:text-[var(--ink)]"
										:aria-label="`About ${field.label}`"
										@click="pinned = pinned === field.fieldname ? '' : field.fieldname"
									>?</button>
									<span
										v-if="hovered === field.fieldname || pinned === field.fieldname"
										class="absolute left-5 top-0 z-20 w-[22rem] max-w-[70vw] rounded-lg border border-[var(--rule-strong)] bg-[var(--paper)] p-3 text-[12px] font-normal leading-relaxed text-[var(--ink-soft)] shadow-lg"
									>{{ field.description }}</span>
								</span>

								<span v-if="changed(field)" class="text-[11px] text-[var(--ink-faint)]">edited</span>
							</div>
							<p v-if="field.read_only" class="mt-0.5 text-[11.5px] text-[var(--ink-faint)]">
								Set by this app, not by hand.
							</p>
						</div>

						<div class="w-full shrink-0 sm:w-[19rem]">
							<button
								v-if="field.fieldtype === 'Check'"
								role="switch"
								:aria-checked="String(Boolean(draft[field.fieldname]))"
								class="relative h-[22px] w-[38px] rounded-full border transition-colors duration-200"
								:class="draft[field.fieldname]
									? 'border-[var(--ink)] bg-[var(--ink)]'
									: 'border-[var(--rule-strong)] bg-[var(--paper-sunk)]'"
								:disabled="field.read_only"
								@click="draft[field.fieldname] = draft[field.fieldname] ? 0 : 1"
							>
								<span
									class="absolute top-[2px] h-[16px] w-[16px] rounded-full bg-[var(--paper)] shadow-sm transition-all duration-200 ease-[var(--ease)]"
									:class="draft[field.fieldname] ? 'left-[18px]' : 'left-[2px]'"
									:style="!draft[field.fieldname] ? { background: 'var(--ink-ghost)' } : null"
								/>
							</button>

							<select
								v-else-if="field.fieldtype === 'Select'"
								v-model="draft[field.fieldname]"
								:disabled="field.read_only"
								class="w-full rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60"
							>
								<option v-for="option in field.options" :key="option" :value="option">{{ option }}</option>
							</select>

							<textarea
								v-else-if="field.fieldtype === 'Small Text'"
								v-model="draft[field.fieldname]"
								rows="3"
								:disabled="field.read_only"
								class="w-full rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60"
							/>

							<input
								v-else
								v-model="draft[field.fieldname]"
								:type="field.fieldtype === 'Password' ? 'password' : 'text'"
								:inputmode="field.fieldtype === 'Int' ? 'numeric' : undefined"
								:disabled="field.read_only"
								:placeholder="field.fieldtype === 'Password' && field.has_value
									? 'set — leave blank to keep it'
									: ''"
								class="w-full rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60"
								:class="field.fieldtype === 'Password' || field.fieldtype === 'Int' ? 'u-mono' : ''"
							/>
						</div>
					</div>
				</div>
			</section>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import { loadSettings } from "../state";
import {
	runIngestResource,
	saveSettingsResource,
	settingsFormResource,
	systemHealthResource,
} from "../api";

const formRes = settingsFormResource();
const healthRes = systemHealthResource();
const saveRes = saveSettingsResource();

const active = ref("");
const hovered = ref("");
//: Clicking the marker keeps a description open, for one worth reading twice.
const pinned = ref("");
const saving = ref(false);
const ingesting = ref(false);

/** What is on the server, and what the form has been changed to. */
const original = reactive({});
const draft = reactive({});

const groups = computed(() => formRes.data?.groups || []);
const loading = computed(() => formRes.loading && !formRes.data);
const checkpoints = computed(() => healthRes.data?.checkpoints || []);
const activeGroup = computed(() => groups.value.find((g) => g.key === active.value));

const allFields = computed(() => groups.value.flatMap((g) => g.fields));

/**
 * A field differs from what the server holds.
 *
 * A blank password is NOT a change: the form is never given the stored value,
 * so empty means "the one already there", and treating it as an edit would
 * offer to save a secret nobody typed.
 */
function changed(field) {
	if (field.read_only) return false;
	if (field.fieldtype === "Password") return Boolean((draft[field.fieldname] || "").trim());
	return String(draft[field.fieldname] ?? "") !== String(original[field.fieldname] ?? "");
}

const dirtyCount = computed(() => allFields.value.filter(changed).length);
const changedIn = (group) => group.fields.some(changed);

const subtitle = computed(() => {
	if (loading.value) return "loading…";
	if (dirtyCount.value) return `${dirtyCount.value} unsaved`;
	return `${allFields.value.length} settings`;
});

function fill() {
	for (const field of allFields.value) {
		const value = field.fieldtype === "Password" ? "" : (field.value ?? "");
		original[field.fieldname] = value;
		draft[field.fieldname] = value;
	}
	if (!active.value && groups.value.length) active.value = groups.value[0].key;
}

function reset() {
	for (const field of allFields.value) draft[field.fieldname] = original[field.fieldname];
}

async function save() {
	saving.value = true;
	try {
		const values = {};
		for (const field of allFields.value) {
			if (changed(field)) values[field.fieldname] = draft[field.fieldname];
		}
		const result = await saveRes.submit({ values });
		toast.success(`Saved ${result.saved.length} setting${result.saved.length === 1 ? "" : "s"}`);
		await formRes.fetch();
		fill();
		// The sidebar carries the monitoring indicator, which one of these
		// switches off.
		loadSettings(true);
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not save");
	} finally {
		saving.value = false;
	}
}

async function ingestNow() {
	ingesting.value = true;
	try {
		const result = await runIngestResource().submit({});
		// A run that did not happen is not a success.
		//
		// With monitoring off, run_ingest returns {source: "disabled", reason:
		// "..."} and no `error` key — so this showed a green "Read 0, inserted
		// 0". On a security console that reads as "collection works and the
		// server is quiet", which is the most dangerous thing it could say.
		const didNotRun = result.error || result.reason || ["disabled", "none"].includes(result.source);
		if (didNotRun) {
			toast.error(result.error || result.reason || `No log source available (${result.source}).`);
		} else if (result.behind) {
			toast.error(
				`Read ${result.read ?? 0}, inserted ${result.inserted ?? 0} — and the log is still ` +
					"ahead of us. Something is producing events faster than they can be collected.",
			);
		} else {
			toast.success(`Read ${result.read ?? 0}, inserted ${result.inserted ?? 0}`);
		}
		healthRes.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Ingest failed");
	} finally {
		ingesting.value = false;
	}
}

onMounted(async () => {
	await formRes.fetch();
	fill();
	healthRes.fetch();
});
</script>
