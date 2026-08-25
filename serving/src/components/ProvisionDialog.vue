<template>
	<Dialog
		v-model="open"
		:options="{ title: 'Build a new bench', size: '3xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<!--
					A step rail rather than a wizard that hides where you are.
					Four panels is few enough to show all of them, and knowing
					that a password is coming changes whether somebody starts.
				-->
				<ol class="flex items-center gap-1.5 text-[11.5px]">
					<li v-for="(panel, index) in PANELS" :key="panel.key" class="flex items-center gap-1.5">
						<button
							type="button"
							class="rounded px-2 py-1 transition-colors"
							:class="index === stepIndex
								? 'bg-[var(--paper-sunk)] font-medium text-[var(--ink)]'
								: 'text-[var(--ink-faint)] hover:text-[var(--ink)]'"
							:disabled="index > furthest"
							@click="stepIndex = index"
						>
							{{ index + 1 }}. {{ panel.label }}
						</button>
						<span v-if="index < PANELS.length - 1" class="text-[var(--ink-ghost)]">›</span>
					</li>
				</ol>

				<!-- 1. Basics -->
				<template v-if="step === 'basics'">
					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Bench name</span>
							<input v-model.trim="form.bench_name" placeholder="fb-16-new"
							       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								Becomes a directory under <span class="u-mono">{{ benchRoot }}</span>.
							</span>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Frappe version</span>
							<select v-model="form.frappe_version"
							        class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
								<option value="16">version-16</option>
								<option value="15">version-15</option>
							</select>
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								Decides the branch and the Python. v16 needs 3.14, v15 runs on 3.12 —
								the checks below say whether it is there.
							</span>
						</label>
					</div>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Site name</span>
						<input v-model.trim="form.site_name" placeholder="app.example.com (optional)"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							Left empty the bench is built with no site on it, and no database
							password is needed.
						</span>
					</label>

					<!-- Answered as it is typed, so nobody starts a four-gigabyte
					     build that was going to fail on a name that is taken. -->
					<div v-if="checks.length" class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] p-3">
						<p class="u-label mb-2">Before it starts</p>
						<ul class="flex flex-col gap-1.5">
							<li v-for="c in checks" :key="c.key" class="flex items-start gap-2 text-[12.5px]">
								<Icon :name="c.ok ? 'check' : 'alert'" :size="14"
								      class="mt-[2px] shrink-0" :class="c.ok ? 'u-ok' : (c.blocking ? 'u-danger' : 'u-warn')" />
								<span>
									<span :class="c.ok ? '' : 'font-medium'">{{ c.label }}</span>
									<span class="text-[var(--ink-faint)]"> — {{ c.detail }}</span>
								</span>
							</li>
						</ul>
						<p v-if="ports.webserver" class="mt-2 text-[11.5px] text-[var(--ink-faint)]">
							Ports {{ ports.webserver }}, {{ ports.socketio }}, {{ ports.redis_queue }},
							{{ ports.redis_cache }} — the lowest block nothing else is using.
						</p>
						<p v-if="portError" class="mt-2 text-[12px] u-danger">{{ portError }}</p>
					</div>
				</template>

				<!-- 2. Apps -->
				<template v-else-if="step === 'apps'">
					<p class="text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
						Fetched in the order listed, then installed on the site in the same order —
						an app that depends on another has to come after it. frappe is always there;
						it is what a bench is.
					</p>

					<div v-if="form.apps.length" class="flex flex-col gap-1.5">
						<div v-for="(app, index) in form.apps" :key="index"
						     class="flex items-center gap-2 rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5">
							<span class="u-mono flex-1 text-[13px]">{{ app.repo }}</span>
							<span class="text-[11.5px] text-[var(--ink-faint)]">{{ app.profile }}</span>
							<span v-if="app.branch" class="u-mono text-[11.5px] text-[var(--ink-faint)]">{{ app.branch }}</span>
							<button class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--danger)]"
							        @click="form.apps.splice(index, 1)">remove</button>
						</div>
					</div>
					<p v-else class="text-[12.5px] text-[var(--ink-faint)]">No extra apps — frappe only.</p>

					<div class="grid gap-2 sm:grid-cols-[1fr_1.4fr_1fr_auto] sm:items-end">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Account</span>
							<select v-model="picker.profile" @change="loadRepos"
							        class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
								<option value="" disabled>choose</option>
								<option v-for="p in profiles" :key="p.name" :value="p.name">{{ p.name }}</option>
							</select>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Repository</span>
							<SearchSelect v-model="picker.repo" :options="repoOptions" mono
							              placeholder="Choose a repository" :loading="repos.loading" />
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Branch</span>
							<input v-model.trim="picker.branch" placeholder="default"
							       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						</label>
						<Button :disabled="!picker.repo" @click="addApp">Add</Button>
					</div>
				</template>

				<!-- 3. Domain -->
				<template v-else-if="step === 'domain'">
					<p class="text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
						Optional. A DNS record on its own does not make the site serve the name —
						the domain also has to be added to the site and nginx reloaded, and the last
						of those needs root this app does not have. Whatever is left will be printed
						in the log for you to run.
					</p>
					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Domain</span>
							<input v-model.trim="form.domain" placeholder="app.example.com (optional)"
							       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Set it automatically with</span>
							<select v-model="form.domain_provider"
							        class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
								<option value="">Do not touch DNS — I will point it myself</option>
								<option v-for="p in providers" :key="p.name" :value="p.name">
									{{ p.provider_name }} ({{ p.provider }})
								</option>
							</select>
							<RouterLink v-if="!providers.length" :to="{ name: 'DomainProviders' }"
							            class="text-[11.5px] text-[var(--ink-faint)] underline underline-offset-2">
								No providers configured yet
							</RouterLink>
						</label>
					</div>
				</template>

				<!-- 4. Confirm -->
				<template v-else>
					<div class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] p-3 text-[12.5px]">
						<p><b>{{ form.bench_name }}</b> on frappe version-{{ form.frappe_version }},
							at <span class="u-mono">{{ benchRoot }}/{{ form.bench_name }}</span>.</p>
						<p v-if="form.site_name" class="mt-1">
							Site <span class="u-mono">{{ form.site_name }}</span>{{ form.apps.length
								? ` with ${form.apps.map((a) => a.repo).join(", ")}` : "" }}.
						</p>
						<p v-else class="mt-1">No site — the bench only.</p>
						<p v-if="form.domain" class="mt-1">
							Domain <span class="u-mono">{{ form.domain }}</span>{{ form.domain_provider
								? ` via ${form.domain_provider}` : ", pointed by hand" }}.
						</p>
						<p class="mt-1 text-[var(--ink-faint)]">
							Ports {{ ports.webserver }}/{{ ports.socketio }}. Assets skipped.
						</p>
					</div>

					<template v-if="form.site_name">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Database root password</span>
							<input v-model="form.db_root_password" type="password" autocomplete="new-password"
							       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								bench has no way to take this except on the command line. It is redacted
								out of the stored command and deleted the moment the job finishes.
							</span>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Administrator password</span>
							<input v-model="form.admin_password" type="password" autocomplete="new-password"
							       placeholder="optional — frappe generates one and prints it"
							       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						</label>
					</template>

					<div class="u-note u-note-danger flex flex-col gap-1.5">
						<span class="u-label">
							Type <span class="u-mono normal-case">{{ form.bench_name }}</span> to confirm
						</span>
						<input v-model.trim="confirm" type="text" autocomplete="off" :placeholder="form.bench_name"
						       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] leading-relaxed">
							This takes several minutes and about four gigabytes{{ form.site_name
								? ", and creates a database" : "" }}. Cancelling stops the job but
							leaves whatever was built on the disk.
						</span>
					</div>
				</template>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex items-center justify-between gap-2">
				<Button v-if="stepIndex > 0" :disabled="busy" @click="stepIndex -= 1">Back</Button>
				<span v-else />
				<div class="flex items-center gap-2">
					<div v-if="preflight.loading" class="flex items-center gap-2 text-[12.5px] text-[var(--ink-faint)]">
						<Spinner class="h-3.5 w-3.5" /><span>Checking…</span>
					</div>
					<Button :disabled="busy" @click="open = false">Cancel</Button>
					<Button v-if="step !== 'confirm'" variant="solid" :disabled="!canAdvance" @click="next">
						Next
					</Button>
					<Button v-else variant="solid" :loading="running" :disabled="!canRun" @click="run">
						Build it
					</Button>
				</div>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";
import { RouterLink } from "vue-router";

import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { watchJob } from "../jobs";
import { useBusyGuard } from "../busy";
import {
	domainProvidersResource,
	githubProfilesResource,
	profileReposResource,
	provisionPreflightResource,
	runProvisionResource,
} from "../api";

const PANELS = [
	{ key: "basics", label: "Bench" },
	{ key: "apps", label: "Apps" },
	{ key: "domain", label: "Domain" },
	{ key: "confirm", label: "Confirm" },
];

const props = defineProps({ modelValue: { type: Boolean, default: false } });
const emit = defineEmits(["update:modelValue", "started"]);

const preflight = provisionPreflightResource();
const runResource = runProvisionResource();
const profilesRes = githubProfilesResource();
const repos = profileReposResource();
const providersRes = domainProvidersResource();

const blank = () => ({
	bench_name: "",
	frappe_version: "16",
	site_name: "",
	apps: [],
	domain: "",
	domain_provider: "",
	db_root_password: "",
	admin_password: "",
});

const form = ref(blank());
const picker = ref({ profile: "", repo: null, branch: "" });
const stepIndex = ref(0);
const furthest = ref(0);
const confirm = ref("");
const running = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (value) => emit("update:modelValue", value),
});

const step = computed(() => PANELS[stepIndex.value].key);
const busy = computed(() => running.value);
useBusyGuard(busy);

const checks = computed(() => preflight.data?.checks || []);
const ports = computed(() => preflight.data?.ports || {});
const portError = computed(() => preflight.data?.port_error || "");
const benchRoot = computed(() => preflight.data?.bench_root || "the bench root");
const profiles = computed(() => profilesRes.data || []);
const providers = computed(() => providersRes.data?.providers || []);
const repoOptions = computed(() =>
	(repos.data || []).map((r) => ({ value: r.repo_name, label: r.repo_name, description: r.description })),
);

// Blocking checks only. A memory warning is a reason this might not finish,
// not a reason to refuse to start it.
const basicsReady = computed(
	() =>
		!!form.value.bench_name &&
		!portError.value &&
		checks.value.length > 0 &&
		checks.value.every((c) => c.ok || !c.blocking),
);
const canAdvance = computed(() => (step.value === "basics" ? basicsReady.value : true));
const canRun = computed(
	() =>
		basicsReady.value &&
		confirm.value === form.value.bench_name &&
		(!form.value.site_name || !!form.value.db_root_password),
);

function next() {
	stepIndex.value = Math.min(stepIndex.value + 1, PANELS.length - 1);
	furthest.value = Math.max(furthest.value, stepIndex.value);
}

function addApp() {
	if (!picker.value.repo) return;
	form.value.apps.push({
		profile: picker.value.profile,
		repo: picker.value.repo.value,
		branch: picker.value.branch,
	});
	picker.value.repo = null;
	picker.value.branch = "";
}

function loadRepos() {
	if (picker.value.profile) repos.submit({ profile: picker.value.profile }).catch(() => {});
}

// Re-checked as the name or version changes, debounced so a typed name does
// not fire a request per keystroke.
let timer;
watch(
	() => [form.value.bench_name, form.value.site_name, form.value.frappe_version],
	() => {
		clearTimeout(timer);
		if (!form.value.bench_name) return;
		timer = setTimeout(() => {
			preflight
				.submit({
					bench_name: form.value.bench_name,
					site_name: form.value.site_name || null,
					frappe_version: form.value.frappe_version,
					// The tick, not the value: a password should not travel to the
					// server until the moment it is actually needed. The check
					// only asks whether one WILL be supplied, and the confirm
					// panel is where it actually is.
					has_password: 1,
				})
				.catch(() => {});
		}, 300);
	},
);

watch(
	() => props.modelValue,
	(isOpen) => {
		if (isOpen) {
			form.value = blank();
			picker.value = { profile: "", repo: null, branch: "" };
			stepIndex.value = 0;
			furthest.value = 0;
			confirm.value = "";
			error.value = "";
			profilesRes.fetch();
			providersRes.fetch();
		} else {
			form.value.db_root_password = "";
			form.value.admin_password = "";
		}
	},
);

async function run() {
	if (!canRun.value) return;
	running.value = true;
	error.value = "";
	try {
		const result = await runResource.submit({
			bench_name: form.value.bench_name,
			frappe_version: form.value.frappe_version,
			site_name: form.value.site_name || null,
			apps: JSON.stringify(form.value.apps),
			db_root_password: form.value.db_root_password || null,
			admin_password: form.value.admin_password || null,
			domain: form.value.domain || null,
			domain_provider: form.value.domain_provider || null,
			skip_assets: 1,
			confirm: confirm.value,
		});
		watchJob(result.name, {
			operation: "Provision",
			app_name: `Provision · ${form.value.bench_name}`,
			bench: form.value.bench_name,
			status: "Queued",
		});
		toast.success("Building — it will keep going in the dock.");
		open.value = false;
		emit("started", result.name);
	} catch (caught) {
		error.value = caught.messages?.[0] || "The build could not be started.";
	} finally {
		running.value = false;
		form.value.db_root_password = "";
		form.value.admin_password = "";
	}
}
</script>
