<template>
	<AppShell title="Benches" :subtitle="subtitle">
		<template #actions>
			<Button :loading="rescanning" @click="rescan">
				<template #prefix><Icon name="refresh" :size="14" /></template>
				Rescan
			</Button>
		</template>

		<!-- git access, shown here because this is where cloning happens -->
		<section class="u-card mb-3 overflow-hidden">
			<header class="flex items-center justify-between gap-3 border-b border-[var(--rule)] px-4 py-3">
				<div class="flex items-center gap-2">
					<Icon name="key" :size="16" />
					<h2 class="u-display text-[13.5px]">Git access</h2>
				</div>
				<OutcomeMark
					v-if="auth.data"
					:outcome="auth.data.ok ? 'Success' : 'Failure'"
					:label="auth.data.ok ? 'Ready' : `${auth.data.problems.length} issue${auth.data.problems.length === 1 ? '' : 's'}`"
				/>
			</header>

			<div v-if="auth.loading && !auth.data" class="flex flex-col gap-2 p-4">
				<Skeleton v-for="n in 3" :key="n" height="1rem" />
			</div>

			<div v-else-if="auth.data" class="divide-y divide-[var(--rule)]">
				<div class="flex flex-wrap gap-x-8 gap-y-2 px-4 py-3">
					<div v-for="probe in auth.data.probes" :key="probe.host" class="text-[13px]">
						<p class="u-mono">{{ probe.host }}</p>
						<p class="mt-0.5 text-[11.5px] text-[var(--ink-faint)]">
							{{ probe.authenticated_as ? `authenticates as ${probe.authenticated_as}` : "not accepted" }}
						</p>
					</div>
					<div v-for="key in auth.data.keys" :key="key.name" class="text-[13px]">
						<p class="u-mono">{{ key.name }}</p>
						<p class="mt-0.5 text-[11.5px] text-[var(--ink-faint)]">
							{{ key.passphrase_free ? "usable unattended" : "has a passphrase — unusable in a job" }}
						</p>
					</div>
				</div>

				<div v-if="auth.data.problems.length" class="px-4 py-3">
					<ul class="flex flex-col gap-1.5">
						<li v-for="(problem, i) in auth.data.problems" :key="i"
						    class="flex items-start gap-2 text-[12.5px] leading-relaxed">
							<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
							<span>{{ problem }}</span>
						</li>
					</ul>
					<details class="mt-3">
						<summary class="cursor-pointer text-[12px] text-[var(--ink-faint)] hover:text-[var(--ink)]">
							Show the ~/.ssh/config block to add
						</summary>
						<pre class="u-mono u-scroll mt-2 overflow-x-auto rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] p-3 text-[12px] leading-relaxed">{{ auth.data.suggested_ssh_config }}</pre>
						<p class="mt-1.5 text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							Add this yourself and <code class="u-mono">chmod 600 ~/.ssh/config</code>. This app
							will never write to your SSH configuration.
						</p>
					</details>
				</div>
			</div>
		</section>

		<div v-if="loading" class="grid gap-3 lg:grid-cols-2">
			<div v-for="n in 4" :key="n" class="u-card p-4">
				<Skeleton height="1.1rem" width="40%" />
				<Skeleton height="0.8rem" width="70%" class="mt-2" />
				<Skeleton height="3rem" class="mt-3" />
			</div>
		</div>

		<div v-else-if="benches.length" class="u-stagger grid gap-3 lg:grid-cols-2">
			<article v-for="bench in benches" :key="bench.name" class="u-card overflow-hidden">
				<header class="flex items-start justify-between gap-3 border-b border-[var(--rule)] px-4 py-3">
					<div class="min-w-0">
						<h3 class="u-display truncate text-[14px]">{{ bench.name }}</h3>
						<p class="u-mono truncate text-[11.5px] text-[var(--ink-faint)]">{{ bench.bench_path }}</p>
					</div>
					<RouterLink
						:to="{ name: 'Installs', query: { bench: bench.name } }"
						class="shrink-0 rounded-md border border-[var(--rule)] px-2 py-1 text-[12px] transition-colors hover:bg-[var(--paper-sunk)]"
					>Install app</RouterLink>
				</header>

				<dl class="grid grid-cols-4 divide-x divide-[var(--rule)] border-b border-[var(--rule)] text-center">
					<div class="px-2 py-2.5">
						<dt class="u-label">Web</dt>
						<dd class="u-num mt-0.5 text-[13px]">{{ bench.webserver_port || "—" }}</dd>
					</div>
					<div class="px-2 py-2.5">
						<dt class="u-label">Socket</dt>
						<dd class="u-num mt-0.5 text-[13px]">{{ bench.socketio_port || "—" }}</dd>
					</div>
					<div class="px-2 py-2.5">
						<dt class="u-label">Frappe</dt>
						<dd class="mt-0.5 text-[13px]">{{ bench.frappe_branch || "—" }}</dd>
					</div>
					<div class="px-2 py-2.5">
						<dt class="u-label">Python</dt>
						<dd class="u-num mt-0.5 text-[13px]">{{ bench.python_version || "—" }}</dd>
					</div>
				</dl>

				<div class="px-4 py-3">
					<p class="u-label mb-1.5">{{ bench.apps.length }} apps</p>
					<ul class="flex flex-wrap gap-1">
						<li
							v-for="app in bench.apps"
							:key="app.app_name"
							class="inline-flex items-center gap-1.5 rounded border border-[var(--rule)] px-1.5 py-[3px] text-[12px]"
							:title="`${app.git_url || 'no remote'} · ${app.branch || 'unknown branch'}${app.is_dirty ? ' · uncommitted changes' : ''}`"
						>
							<span class="u-mono">{{ app.app_name }}</span>
							<span class="text-[10.5px] text-[var(--ink-faint)]">{{ app.branch }}</span>
							<span v-if="app.is_dirty" class="h-1 w-1 rounded-full bg-[var(--ink)]" title="uncommitted changes" />
						</li>
					</ul>

					<p class="u-label mb-1.5 mt-3">{{ bench.sites.length }} sites</p>
					<ul class="flex flex-wrap gap-1">
						<li v-for="site in bench.sites" :key="site.site_name"
						    class="u-mono rounded border border-[var(--rule)] px-1.5 py-[3px] text-[12px]">
							{{ site.site_name }}
							<span v-if="site.is_default" class="ml-1 text-[10.5px] text-[var(--ink-faint)]">default</span>
						</li>
					</ul>
				</div>
			</article>
		</div>

		<EmptyState
			v-else
			title="No benches found"
			icon="layers"
			hint="Nothing under the configured Bench Root looks like a bench. A directory counts only if it has apps, sites, config, logs and config/pids."
		/>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import Skeleton from "../components/Skeleton.vue";
import { benchesResource, gitAuthResource, rescanBenchesResource } from "../api";

const resource = benchesResource();
const auth = gitAuthResource();
const rescanning = ref(false);

const benches = computed(() => resource.data || []);
const loading = computed(() => resource.loading && !resource.data);
const subtitle = computed(() =>
	loading.value ? "scanning…" : `${benches.value.length} found on this machine`,
);

async function rescan() {
	rescanning.value = true;
	try {
		const result = await rescanBenchesResource().submit({});
		toast.success(`Found ${result.found} bench${result.found === 1 ? "" : "es"} under ${result.root}`);
		resource.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Rescan failed");
	} finally {
		rescanning.value = false;
	}
}

onMounted(() => {
	resource.fetch();
	auth.fetch();
});
</script>
