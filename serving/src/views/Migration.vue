<template>
	<AppShell :title="title" :subtitle="subtitle">
		<template #actions>
			<RouterLink
				:to="{ name: 'Migrations' }"
				class="text-[12.5px] text-[var(--ink-faint)] underline-offset-2 hover:underline"
			>All moves</RouterLink>
			<Button v-if="canResume" variant="solid" :loading="acting" @click="resume">
				{{ retryCount ? `Retry ${retryCount} and continue` : "Continue" }}
			</Button>
			<Button v-if="canStop" :loading="acting" @click="stop">Stop</Button>
		</template>

		<div v-if="loading && !data" class="space-y-2">
			<Skeleton v-for="n in 5" :key="n" class="h-12" />
		</div>

		<template v-else-if="data">
			<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
				{{ data.source_bench }} on {{ data.source_server }} → {{ data.target_bench }}.
				Each step is an ordinary job, so it appears in the dock while it runs and in the
				deployment or restoration log afterwards.
			</p>

			<!--
				Paused is not Failed, and the wording matters: the bench exists
				and some sites are already across. Continuing picks up at the
				step that stopped rather than starting again.
			-->
			<!--
				Only shown when it is actually needed. Every terminal state
				clears the password, so continuing a stopped move needs it
				again — and "it was cleared, start over" cost an hour of
				re-cloning to work around.
			-->
			<div v-if="askingPassword" class="u-note mb-4 flex flex-col gap-2">
				<p class="text-[12.5px] leading-relaxed">
					The database root password was cleared when this move stopped — it is never kept
					longer than a run needs it. Supply it again to continue. Nothing already done is
					repeated.
				</p>
				<div class="flex flex-wrap items-center gap-2">
					<input
						v-model="password"
						type="password"
						placeholder="Database root password"
						class="min-w-0 flex-1 rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						@keyup.enter="resume"
					/>
					<Button variant="solid" :loading="acting" :disabled="!password" @click="resume">
						Continue
					</Button>
					<Button variant="ghost" @click="askingPassword = false; password = ''">Cancel</Button>
				</div>
			</div>

			<p v-if="data.notes" class="u-note mb-4 text-[12.5px] leading-relaxed"
			   :class="data.status === 'Paused' ? 'u-note-danger' : ''">
				{{ data.notes }}
			</p>

			<ol class="flex flex-col gap-1.5">
				<li
					v-for="(action, i) in data.actions"
					:key="i"
					class="flex flex-wrap items-center gap-3 rounded-lg border px-3 py-2.5"
					:class="i === data.current_action && running
						? 'border-[var(--ink)]'
						: 'border-[var(--rule)]'"
				>
					<span class="w-5 shrink-0 text-[11.5px] text-[var(--ink-faint)]">{{ i + 1 }}</span>
					<Icon :name="markFor(i).icon" :size="14" class="shrink-0" :class="markFor(i).class" />
					<span class="text-[13px]">{{ action.label }}</span>
					<span class="u-mono text-[11.5px] text-[var(--ink-faint)]">{{ action.kind }}</span>

					<span class="ml-auto flex items-center gap-3">
						<!--
							Straight to the job, not to the list page that
							happens to carry its operation. A clone made by a
							migration is an App Install, a bench build is a
							Deployment and a site move is a Restoration — three
							different pages, and sending all of them to one of
							the three is how "click the failing step" opened a
							page with nothing on it.
						-->
						<RouterLink
							v-if="jobFor(i)"
							:to="{ name: jobRoute(action), query: { job: jobFor(i).name } }"
							class="text-[11.5px] underline-offset-2 hover:underline"
							:class="failed(i) ? 'u-danger' : 'text-[var(--ink-faint)]'"
						>{{ jobFor(i).status }} — read the log</RouterLink>
						<span v-else class="text-[11.5px] text-[var(--ink-faint)]">{{ markFor(i).label }}</span>
					</span>

					<!-- The reason, on the page that shows it stopping. -->
					<p v-if="failed(i) && jobFor(i).error_summary"
					   class="u-note u-note-danger w-full text-[12px] leading-relaxed">
						{{ jobFor(i).error_summary }}
					</p>
				</li>
			</ol>
		</template>

		<EmptyState v-else title="No such migration" hint="It may have been removed." />
	</AppShell>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";
import { useRoute } from "vue-router";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import { cancelMigrationResource, migrationResource, resumeMigrationResource } from "../api";

const POLL_MS = 4000;

const route = useRoute();
const resource = migrationResource();
const resumeRes = resumeMigrationResource();
const cancelRes = cancelMigrationResource();

const acting = ref(false);
let timer = null;

const data = computed(() => resource.data);
const loading = computed(() => resource.loading);
const running = computed(() => data.value?.status === "Running");
// Cancelled counts as stopped. Stopping a move by hand ends the chain; it does
// not void the plan or undo what it had already done — and refusing to
// continue one meant a new migration was the only way forward, which is the
// thing this page exists to avoid.
const canResume = computed(() => ["Paused", "Cancelled", "Failed"].includes(data.value?.status));
/** How many actions Continue would retry rather than skip past. */
const retryCount = computed(() => (data.value?.failed || []).length);

const askingPassword = ref(false);
const password = ref("");
const canStop = computed(() => ["Running", "Paused"].includes(data.value?.status));

const title = computed(() => `Move · ${data.value?.target_bench || route.params.name}`);
const subtitle = computed(() => {
	if (!data.value) return "loading…";
	const total = data.value.actions.length;
	const at = Math.min(data.value.current_action + (running.value ? 1 : 0), total);
	return `${data.value.status.toLowerCase()} · step ${at} of ${total}`;
});

/** The job this action produced, matched by position among jobs of its kind. */
function jobFor(index) {
	return (data.value?.jobs || [])[index];
}

const ROUTE_FOR_KIND = {
	restore: "RestoreLogs",
	provision: "DeploymentLogs",
	clone: "InstallLogs",
};

function jobRoute(action) {
	return ROUTE_FOR_KIND[action.kind] || "Installs";
}

function failed(index) {
	if (data.value?.states?.[index] === "Failed") return true;
	const job = jobFor(index);
	return Boolean(job) && !["Success", "Queued", "Running", "Completed With Warnings"].includes(job.status);
}

function markFor(index) {
	// Per-action state, not a pointer. A pointer cannot say "the first app did
	// not clone and the two after it did", which is exactly what a batch of
	// clones looks like once it is allowed to finish.
	const state = data.value?.states?.[index];
	if (state === "Success") return { icon: "check", class: "u-ok", label: "done" };
	if (state === "Failed") return { icon: "alert", class: "u-danger", label: "did not complete" };

	const current = data.value?.current_action ?? 0;
	if (index === current && running.value) return { icon: "refresh", class: "", label: "running" };
	if (index === current && canResume.value) return { icon: "alert", class: "u-danger", label: "stopped here" };
	return { icon: "chevron", class: "text-[var(--ink-ghost)]", label: "waiting" };
}

function load() {
	resource.submit({ name: route.params.name }).catch(() => {});
}

async function resume() {
	// The password is cleared whenever a migration reaches a terminal state —
	// deliberately, it is a database root password. Asked for again rather
	// than failing after the button is pressed.
	if (data.value?.needs_password && !password.value) {
		askingPassword.value = true;
		return;
	}

	acting.value = true;
	try {
		await resumeRes.submit({
			name: route.params.name,
			db_root_password: password.value || null,
		});
		askingPassword.value = false;
		password.value = "";
		toast.success("Continuing");
		load();
	} catch (caught) {
		toast.error(caught.messages?.[0] || "Could not continue it");
	} finally {
		acting.value = false;
	}
}

async function stop() {
	acting.value = true;
	try {
		await cancelRes.submit({ name: route.params.name });
		// The job already running is left alone: killing a restore mid-flight
		// leaves a half-loaded database, which is worse than one extra site
		// having moved.
		toast.success("Stopped. Any step already running will finish.");
		load();
	} catch (caught) {
		toast.error(caught.messages?.[0] || "Could not stop it");
	} finally {
		acting.value = false;
	}
}

onMounted(() => {
	load();
	// Polled rather than pushed, for the same reason the job dock is: this app
	// has no socket client, and a poll is what survives a page reload.
	timer = setInterval(() => {
		if (running.value) load();
	}, POLL_MS);
});
onBeforeUnmount(() => clearInterval(timer));
</script>
