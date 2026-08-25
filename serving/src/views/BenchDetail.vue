<template>
	<AppShell :title="name" :subtitle="subtitle">
		<template #actions>
			<Button @click="showCommands = true">
				<template #prefix><Icon name="terminal" :size="14" /></template>
				Bench Commands
			</Button>
			<Button @click="showSsl = true">
				<template #prefix><Icon name="lock" :size="14" /></template>
				Set SSL
			</Button>
			<Button @click="showLogs = true">
				<template #prefix><Icon name="layers" :size="14" /></template>
				Logs
			</Button>
			<ActionMenu label="Actions" :options="actions" />
		</template>

		<BenchCommandDialog
			v-model="showCommands"
			:bench="name"
			:sites="bench.sites.map((s) => s.site_name)"
			:default-site="bench.default_site || ''"
			@started="onStarted"
		/>

		<SslDialog v-model="showSsl" :bench="name" @started="onStarted" />

		<LogsDialog v-model="showLogs" :bench="name" />

		<SiteConfigDialog
			v-model="showConfig"
			:bench="name"
			:sites="bench.sites.map((s) => s.site_name)"
			:default-site="bench.default_site || ''"
		/>

		<BackupsDialog
			v-model="showBackups"
			:bench="name"
			:sites="bench.sites.map((s) => s.site_name)"
			:default-site="bench.default_site || ''"
			@started="onStarted"
		/>

		<RestoreDialog
			v-model="showRestore"
			:bench="name"
			:bench-path="bench.bench_path || ''"
			:sites="bench.sites.map((s) => s.site_name)"
			:default-site="bench.default_site || ''"
			@started="onStarted"
		/>

		<InstallDialog
			v-model="showInstall"
			:bench="name"
			:sites="bench.sites.map((s) => s.site_name)"
			:initial-operation="installMode"
			@started="onStarted"
		/>

		<!-- breadcrumb back, since this page is reached by drilling in -->
		<RouterLink
			:to="{ name: 'Benches' }"
			class="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-[var(--ink-faint)] transition-colors hover:text-[var(--ink)]"
		>
			<Icon name="chevron" :size="13" class="rotate-180" />
			All benches
		</RouterLink>

		<div
			v-if="bench.exists_on_disk === false"
			class="mb-3 flex items-start gap-3 rounded-lg border border-[var(--ink)] bg-[var(--paper-sunk)] px-4 py-3"
		>
			<Icon name="alert" :size="17" class="mt-0.5 shrink-0" />
			<div>
				<p class="text-[13px] font-medium">This bench is no longer on disk</p>
				<p class="mt-0.5 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">
					The record is kept so the install history that referenced it stays readable, but no
					command can run against it.
				</p>
			</div>
		</div>

		<div v-if="loading" class="flex flex-col gap-3">
			<Skeleton height="5rem" />
			<Skeleton height="12rem" />
		</div>

		<template v-else>
			<!-- facts -->
			<section class="u-card u-enter mb-3 overflow-hidden">
				<dl class="grid grid-cols-2 divide-x divide-y divide-[var(--rule)] sm:grid-cols-3 lg:grid-cols-6">
					<div v-for="fact in facts" :key="fact.label" class="px-4 py-3">
						<dt class="u-label">{{ fact.label }}</dt>
						<dd class="u-num mt-1 truncate text-[13.5px]" :class="fact.mono ? 'u-mono' : ''"
						    :title="String(fact.value ?? '')">
							{{ fact.value ?? "—" }}
						</dd>
					</div>
				</dl>
				<p class="u-mono border-t border-[var(--rule)] bg-[var(--paper-sunk)] px-4 py-2 text-[12px] text-[var(--ink-soft)]">
					{{ bench.bench_path }}
				</p>
			</section>

			<div class="grid gap-3 lg:grid-cols-2">
				<section class="u-card overflow-hidden">
					<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
						<h2 class="u-display text-[13.5px]">Apps</h2>
						<span class="text-[11.5px] text-[var(--ink-faint)]">{{ bench.apps.length }}</span>
					</header>
					<div class="u-scroll overflow-x-auto">
						<table class="w-full border-collapse text-left">
							<thead>
								<tr class="border-b border-[var(--rule)] bg-[var(--paper-sunk)]">
									<th class="u-label px-3 py-1.5 font-medium">App</th>
									<th class="u-label px-3 py-1.5 font-medium">Branch</th>
									<th class="u-label px-3 py-1.5 font-medium">Commit</th>
									<th class="u-label px-3 py-1.5 font-medium">Remote</th>
								</tr>
							</thead>
							<tbody>
								<tr v-for="app in bench.apps" :key="app.app_name"
								    class="border-b border-[var(--rule)] last:border-0 hover:bg-[var(--paper-sunk)]">
									<td class="u-mono px-3 py-2 text-[13px]">
										{{ app.app_name }}
										<span v-if="app.is_dirty" class="ml-1.5 inline-block h-1.5 w-1.5 rounded-full bg-[var(--ink)]"
										      title="uncommitted or untracked changes" />
									</td>
									<td class="px-3 py-2 text-[13px]">{{ app.branch || "—" }}</td>
									<td class="u-mono px-3 py-2 text-[12.5px] text-[var(--ink-faint)]">
										{{ app.commit || "—" }}
										<span v-if="app.is_shallow" class="ml-1 text-[10.5px]">shallow</span>
									</td>
									<td class="px-3 py-2 text-[12.5px] text-[var(--ink-faint)]">
										<span class="u-mono">{{ app.remote_name || "—" }}</span>
										<span v-if="app.git_url" class="ml-1.5 truncate" :title="app.git_url">
											{{ app.git_url.startsWith("git@") ? "ssh" : "https" }}
										</span>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
				</section>

				<div class="flex flex-col gap-3">
					<section class="u-card overflow-hidden">
						<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
							<h2 class="u-display text-[13.5px]">Sites</h2>
							<span class="text-[11.5px] text-[var(--ink-faint)]">{{ bench.sites.length }}</span>
						</header>
						<ul class="divide-y divide-[var(--rule)]">
							<li v-for="site in bench.sites" :key="site.site_name" class="px-4 py-2.5">
								<div class="flex items-center justify-between gap-3">
									<span class="u-mono text-[13px]">{{ site.site_name }}</span>
									<a
										v-if="bench.webserver_port"
										:href="`http://${site.site_name}:${bench.webserver_port}`"
										target="_blank" rel="noreferrer"
										class="shrink-0 text-[11.5px] text-[var(--ink-faint)] underline-offset-2 hover:text-[var(--ink)] hover:underline"
									>open</a>
								</div>
								<p class="mt-1 text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
									{{ site.installed_apps.join(", ") || "no apps installed" }}
								</p>
							</li>
						</ul>
						<EmptyState v-if="!bench.sites.length" title="No sites" icon="layers" />
					</section>

					<section class="u-card overflow-hidden">
						<header class="flex items-baseline justify-between border-b border-[var(--rule)] px-4 py-3">
							<h2 class="u-display text-[13.5px]">Recent installs</h2>
							<RouterLink :to="{ name: 'Installs' }"
							            class="text-[11.5px] text-[var(--ink-faint)] underline-offset-2 hover:underline">
								all
							</RouterLink>
						</header>
						<ul v-if="bench.installs?.length" class="divide-y divide-[var(--rule)]">
							<li v-for="req in bench.installs" :key="req.name"
							    class="flex items-center justify-between gap-3 px-4 py-2 text-[13px]">
								<OutcomeMark
									:outcome="['Success', 'Completed With Warnings'].includes(req.status) ? 'Success' : req.status === 'Failed' ? 'Failure' : 'Info'"
									:label="req.status"
								/>
								<span class="u-mono min-w-0 flex-1 truncate">{{ req.app_name }}</span>
								<span class="shrink-0 text-[11.5px] text-[var(--ink-faint)]">{{ req.name }}</span>
							</li>
						</ul>
						<EmptyState v-else title="Nothing installed from here yet" icon="download" />
					</section>
				</div>
			</div>
		</template>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { Button, toast } from "frappe-ui";
import { useRoute, useRouter } from "vue-router";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import ActionMenu from "../components/ActionMenu.vue";
import BenchCommandDialog from "../components/BenchCommandDialog.vue";
import SslDialog from "../components/SslDialog.vue";
import LogsDialog from "../components/LogsDialog.vue";
import BackupsDialog from "../components/BackupsDialog.vue";
import SiteConfigDialog from "../components/SiteConfigDialog.vue";
import RestoreDialog from "../components/RestoreDialog.vue";
import InstallDialog from "../components/InstallDialog.vue";
import Skeleton from "../components/Skeleton.vue";
import { benchResource, rescanBenchesResource } from "../api";

const route = useRoute();
const router = useRouter();
const resource = benchResource();
const rescanning = ref(false);
const showInstall = ref(false);
const showCommands = ref(false);
const showSsl = ref(false);
const showLogs = ref(false);
const showBackups = ref(false);
const showConfig = ref(false);
const showRestore = ref(false);
const installMode = ref("Clone");

const name = computed(() => String(route.params.name || ""));
const bench = computed(() => resource.data || { apps: [], sites: [], installs: [] });
const loading = computed(() => resource.loading && !resource.data);
const subtitle = computed(() => {
	if (loading.value) return "loading…";
	const b = bench.value;
	const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
	return `${plural(b.apps.length, "app")} · ${plural(b.sites.length, "site")} · frappe ${b.frappe_branch || "?"}`;
});

const facts = computed(() => [
	{ label: "Web", value: bench.value.webserver_port },
	{ label: "Socket.IO", value: bench.value.socketio_port },
	{ label: "Redis queue", value: bench.value.redis_queue_port },
	{ label: "Redis cache", value: bench.value.redis_cache_port },
	{ label: "Python", value: bench.value.python_version },
	{ label: "Bench user", value: bench.value.frappe_user, mono: true },
]);

/**
 * The action menu.
 *
 * `condition` hides anything that cannot run rather than showing it disabled:
 * a greyed-out item invites a click and then explains nothing. Every entry here
 * is something the app can actually do today.
 */
const actions = computed(() => [
	{
		label: "Install an app…",
		icon: "download",
		description: "Clone a repository from a GitHub account",
		onClick: () => openInstall("Clone"),
		condition: () => bench.value.exists_on_disk !== false,
	},
	{
		label: "Update an app…",
		icon: "refresh",
		description: "git pull inside an app already in this bench",
		onClick: () => openInstall("Pull"),
		condition: () => bench.value.exists_on_disk !== false && bench.value.apps.length > 0,
	},
	{
		label: "Run a bench command…",
		icon: "terminal",
		description: "migrate, backup, clear cache, and the rest",
		onClick: () => (showCommands.value = true),
		condition: () => bench.value.exists_on_disk !== false,
	},
	{
		label: "Site configuration…",
		icon: "sliders",
		description: "Maintenance mode, developer mode, host name",
		onClick: () => (showConfig.value = true),
		condition: () => bench.value.exists_on_disk !== false && bench.value.sites.length > 0,
	},
	{
		label: "Manage backups…",
		icon: "database",
		description: "Take one now, or clear out old ones",
		onClick: () => (showBackups.value = true),
		condition: () => bench.value.exists_on_disk !== false && bench.value.sites.length > 0,
	},
	{
		label: "Restore a site…",
		icon: "database",
		description: "Replace a site from one of its backups",
		onClick: () => (showRestore.value = true),
		danger: true,
		condition: () => bench.value.exists_on_disk !== false && bench.value.sites.length > 0,
	},
	{
		label: "Rescan this bench",
		icon: "refresh",
		description: "Re-read apps, sites and git state from disk",
		onClick: rescan,
	},
	{
		label: "Copy bench path",
		icon: "panel",
		description: bench.value.bench_path,
		onClick: () => copy(bench.value.bench_path, "Bench path copied"),
	},
	{
		label: "Open default site",
		icon: "globe",
		description: bench.value.default_site || "no default site",
		onClick: () => openSite(),
		condition: () => Boolean(bench.value.default_site && bench.value.webserver_port),
	},
	{
		label: "Install history",
		icon: "layers",
		description: "Every request that targeted this bench",
		onClick: () => router.push({ name: "Installs" }),
	},
]);

function openInstall(mode) {
	installMode.value = mode;
	showInstall.value = true;
}

/**
 * Nothing to do — the dock picks the job up and follows it from here.
 *
 * This used to push to the Installs page, which threw away the context the
 * user was in the middle of. Staying put is the point.
 */
function onStarted() {
	rescanLater();
}

/**
 * Refresh this bench once the operation has had time to land, so the app list
 * reflects what was just installed without needing a manual rescan.
 */
function rescanLater() {
	setTimeout(load, 4000);
}

async function rescan() {
	rescanning.value = true;
	try {
		await rescanBenchesResource().submit({});
		await load();
		toast.success(`${name.value} rescanned`);
	} catch (error) {
		toast.error(error.messages?.[0] || "Rescan failed");
	} finally {
		rescanning.value = false;
	}
}

async function copy(text, message) {
	try {
		await navigator.clipboard.writeText(text);
		toast.success(message);
	} catch {
		// Clipboard access needs a secure context; over plain http on a LAN
		// address it is simply unavailable, so say so rather than failing mutely.
		toast.error("Clipboard is unavailable outside a secure context");
	}
}

function openSite() {
	window.open(`http://${bench.value.default_site}:${bench.value.webserver_port}`, "_blank", "noreferrer");
}

const load = () =>
	resource.submit({ name: name.value }).catch((error) => {
		toast.error(error.messages?.[0] || `Could not load ${name.value}`);
		router.replace({ name: "Benches" });
	});

watch(name, load);
onMounted(load);
</script>
