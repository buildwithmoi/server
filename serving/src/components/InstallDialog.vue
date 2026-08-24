<template>
	<Dialog v-model="open" :options="{ title: `${verb} · ${bench}`, size: 'xl' }">
		<template #body-content>
			<!-- Clone and Pull are different enough that the choice comes first
			     and is always visible, rather than being inferred from which
			     fields happen to be filled in. -->
			<div class="mb-4 inline-flex overflow-hidden rounded-md border border-[var(--rule)]">
				<button
					v-for="mode in MODES"
					:key="mode.value"
					type="button"
					class="px-3 py-1.5 text-[12.5px] transition-colors duration-150"
					:class="operation === mode.value
						? 'bg-[var(--ink)] font-medium text-[var(--paper)]'
						: 'text-[var(--ink-soft)] hover:bg-[var(--paper-sunk)]'"
					@click="operation = mode.value"
				>{{ mode.label }}</button>
			</div>
			<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
				{{ MODES.find((m) => m.value === operation).hint }}
			</p>

			<!-- ------------------------------------------------------ clone -->
			<div v-if="operation === 'Clone'" class="flex flex-col gap-3.5">
				<div v-if="!profiles.length" class="rounded-md border border-[var(--ink)] bg-[var(--paper-sunk)] px-3 py-2.5">
					<p class="text-[13px] font-medium">No GitHub accounts configured</p>
					<p class="mt-0.5 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">
						Add one to browse repositories by name instead of typing URLs.
					</p>
					<RouterLink :to="{ name: 'GitHubProfiles' }" class="mt-1.5 inline-block text-[12.5px] underline underline-offset-2" @click="open = false">
						Add an account
					</RouterLink>
				</div>

				<label v-else class="flex flex-col gap-1.5">
					<span class="u-label">GitHub account</span>
					<select v-model="profile" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
						<option v-for="p in profiles" :key="p.name" :value="p.name">
							{{ p.name }} — {{ p.account }}{{ p.repo_count ? ` (${p.repo_count} repos)` : " (not synced)" }}
						</option>
					</select>
				</label>

				<div v-if="profile" class="flex flex-col gap-1.5">
					<div class="flex items-baseline justify-between">
						<span class="u-label">Repository</span>
						<button type="button" class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
						        :disabled="syncing" @click="sync">
							{{ syncing ? "syncing…" : "re-sync list" }}
						</button>
					</div>
					<Autocomplete
						v-model="repo"
						:options="repoOptions"
						placeholder="Type to search repositories…"
						:loading="reposRes.loading"
					/>
					<p v-if="!repoOptions.length && !reposRes.loading" class="text-[11.5px] text-[var(--ink-faint)]">
						Nothing cached for this account yet — use “re-sync list”.
					</p>
				</div>

				<div v-if="repo" class="flex flex-col gap-1.5">
					<div class="flex items-baseline justify-between">
						<span class="u-label">Branch</span>
						<button
							v-if="branch && branch.value !== defaultBranch"
							type="button"
							class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
							@click="resetBranch"
						>use default ({{ defaultBranch }})</button>
					</div>
					<Autocomplete
						v-model="branch"
						:options="branchOptions"
						:placeholder="branchesRes.loading ? 'loading branches…' : 'Default branch'"
						:loading="branchesRes.loading"
					/>
					<p v-if="branchError" class="text-[11.5px] leading-relaxed text-[var(--ink)]">{{ branchError }}</p>
					<p v-else-if="branchesRes.loading" class="text-[11.5px] text-[var(--ink-faint)]">
						Default branch selected. Loading the full branch list…
					</p>
					<p v-else class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						Clear this to use the repository default.
						{{ branchOptions.length }} branches available.
						<span v-if="branchesRes.data?.truncated">
							Only the first {{ branchOptions.length }} are listed — type the exact name if
							the branch you want is not here.
						</span>
					</p>
				</div>

				<div class="grid gap-3 sm:grid-cols-2">
					<label class="flex flex-col gap-1.5">
						<span class="u-label">Install on site</span>
						<select v-model="site" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
							<option value="">clone only, do not install</option>
							<option v-for="s in sites" :key="s" :value="s">{{ s }}</option>
						</select>
					</label>
					<div class="flex flex-col justify-end gap-2 pb-1">
						<label class="flex items-center gap-2 text-[12.5px]">
							<input v-model="skipAssets" type="checkbox" class="accent-[var(--ink)]" />
							Skip asset build
						</label>
						<label class="flex items-center gap-2 text-[12.5px]">
							<input v-model="overwrite" type="checkbox" class="accent-[var(--ink)]" />
							Overwrite if already present
						</label>
					</div>
				</div>
			</div>

			<!-- ------------------------------------------------------- pull -->
			<div v-else class="flex flex-col gap-3.5">
				<div class="flex flex-col gap-1.5">
					<span class="u-label">App</span>
					<Autocomplete v-model="app" :options="appOptions" placeholder="Type to search apps…"
					              :loading="appsRes.loading" />
					<p v-if="selectedApp" class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						on <span class="u-mono">{{ selectedApp.branch }}</span> via
						<span class="u-mono">{{ selectedApp.remote_name }}</span>
						<span v-if="selectedApp.is_shallow"> · shallow clone</span>
					</p>
				</div>

				<div
					v-if="selectedApp?.is_dirty"
					class="flex items-start gap-2.5 rounded-md border border-[var(--ink)] bg-[var(--paper-sunk)] px-3 py-2.5"
				>
					<Icon name="alert" :size="15" class="mt-0.5 shrink-0" />
					<p class="text-[12.5px] leading-relaxed">
						This checkout has uncommitted or untracked changes. The pull will be refused —
						pulling over them would leave a conflicted checkout that this job cannot
						resolve. Commit, stash or discard them first.
					</p>
				</div>

				<label class="flex flex-col gap-1.5">
					<span class="u-label">Branch</span>
					<input v-model.trim="pullBranch" :placeholder="selectedApp?.branch || 'current branch'"
					       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
					<span class="text-[11.5px] text-[var(--ink-faint)]">
						Leave blank to pull the branch the app is already on.
					</span>
				</label>

				<label class="flex items-start gap-2 text-[12.5px]">
					<input v-model="allowMerge" type="checkbox" class="mt-0.5 accent-[var(--ink)]" />
					<span>
						Allow a merge commit
						<span class="block text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							By default the pull is <span class="u-mono">--ff-only</span>, so it refuses rather
							than inventing a merge when the branch has diverged.
						</span>
					</span>
				</label>
			</div>

			<p v-if="error" class="mt-3 flex items-start gap-2 text-[12.5px] leading-relaxed">
				<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
				<span>{{ error }}</span>
			</p>
		</template>

		<template #actions>
			<div class="flex justify-end gap-2">
				<Button @click="open = false">Cancel</Button>
				<Button variant="solid" :loading="submitting" :disabled="!canSubmit" @click="submit">
					{{ verb }}
				</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Autocomplete, Button, Dialog, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import {
	benchAppsResource, createInstallResource, githubProfilesResource,
	profileReposResource, repoBranchesResource, syncGithubProfileResource,
} from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	sites: { type: Array, default: () => [] },
	/** Which tab to open on. The menu has a separate entry for each. */
	initialOperation: { type: String, default: "Clone" },
});
const emit = defineEmits(["update:modelValue", "started"]);

const MODES = [
	{ value: "Clone", label: "Clone a repository",
	  hint: "Runs bench get-app to bring a repository into this bench for the first time." },
	{ value: "Pull", label: "Update an app",
	  hint: "Runs git pull inside an app that is already in this bench, to bring it up to date." },
];

const profilesRes = githubProfilesResource();
const reposRes = profileReposResource();
const branchesRes = repoBranchesResource();
const appsRes = benchAppsResource();

const operation = ref("Clone");
const profile = ref("");
const repo = ref(null);
const branch = ref(null);
const site = ref("");
const skipAssets = ref(true);
const overwrite = ref(false);
const app = ref(null);
const pullBranch = ref("");
const allowMerge = ref(false);
const submitting = ref(false);
const syncing = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (value) => emit("update:modelValue", value),
});

const verb = computed(() => (operation.value === "Pull" ? "Pull" : "Clone"));
const profiles = computed(() => profilesRes.data || []);
const defaultBranch = computed(
	() => repo.value?.defaultBranch || branchesRes.data?.default_branch || "",
);
const branchError = computed(() => branchesRes.data?.error || "");

const repoOptions = computed(() =>
	(reposRes.data || []).map((r) => ({
		label: r.repo_name,
		value: r.repo_name,
		defaultBranch: r.default_branch,
		description: [r.is_private ? "private" : "public", r.is_archived ? "archived" : null,
		              r.description].filter(Boolean).join(" · ").slice(0, 90),
	})),
);

const branchOptions = computed(() =>
	(branchesRes.data?.branches || []).map((b) => ({
		label: b.name,
		value: b.name,
		description: b.name === defaultBranch.value ? "default" : b.protected ? "protected" : "",
	})),
);

const appOptions = computed(() =>
	(appsRes.data || []).map((a) => ({
		label: a.app_name,
		value: a.app_name,
		description: [a.branch, a.is_dirty ? "uncommitted changes" : null].filter(Boolean).join(" · "),
	})),
);

const selectedApp = computed(
	() => (appsRes.data || []).find((a) => a.app_name === app.value?.value) || null,
);

const canSubmit = computed(() =>
	operation.value === "Pull" ? Boolean(app.value?.value) : Boolean(profile.value && repo.value?.value),
);

/* --------------------------------------------------------------- reactions */

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) return;
		error.value = "";
		operation.value = props.initialOperation;
		profilesRes.fetch().then(() => {
			if (!profile.value) {
				profile.value = (profilesRes.data || []).find((p) => p.is_default)?.name
					|| (profilesRes.data || [])[0]?.name
					|| "";
			}
		});
		appsRes.submit({ bench: props.bench });
	},
);

watch(profile, (value) => {
	repo.value = null;
	branch.value = null;
	if (value) reposRes.submit({ profile: value });
});

/**
 * Selecting a repository fills in its default branch IMMEDIATELY, from the
 * cached repo record, and only then starts loading the full branch list.
 *
 * The order matters. Fetching branches first and prefilling afterwards put a
 * multi-second wait on the common path for no benefit: erpnext has over six
 * hundred branches across seven API pages and takes about six seconds, while
 * the default branch was already sitting in the cache. Now the field is usable
 * instantly and the dropdown catches up for the rarer case of wanting a
 * different branch.
 */
watch(repo, async (value) => {
	branch.value = null;
	if (!value?.value || !profile.value) return;

	if (value.defaultBranch) {
		branch.value = { label: value.defaultBranch, value: value.defaultBranch };
	}
	await branchesRes.submit({ profile: profile.value, repo: value.value });
	if (!branch.value && defaultBranch.value) {
		branch.value = { label: defaultBranch.value, value: defaultBranch.value };
	}
});

function resetBranch() {
	branch.value = defaultBranch.value
		? { label: defaultBranch.value, value: defaultBranch.value }
		: null;
}

async function sync() {
	syncing.value = true;
	try {
		const result = await syncGithubProfileResource().submit({ name: profile.value });
		if (result.ok) {
			toast.success(`${result.count} repositories cached`);
			await reposRes.submit({ profile: profile.value });
			profilesRes.fetch();
		} else {
			toast.error(result.error);
		}
	} catch (err) {
		toast.error(err.messages?.[0] || "Sync failed");
	} finally {
		syncing.value = false;
	}
}

async function submit() {
	submitting.value = true;
	error.value = "";
	try {
		const payload =
			operation.value === "Pull"
				? {
						bench: props.bench, operation: "Pull",
						app_name: app.value.value, branch: pullBranch.value || null,
						allow_merge: allowMerge.value,
					}
				: {
						bench: props.bench, operation: "Clone", source_type: "GitHub Profile",
						github_profile: profile.value, repo: repo.value.value,
						branch: branch.value?.value || null, install_on_site: site.value || null,
						skip_assets: skipAssets.value, overwrite_existing: overwrite.value,
					};
		const result = await createInstallResource().submit({ ...payload, run: true });
		toast.success(`${result.name} queued`);
		open.value = false;
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the operation";
	} finally {
		submitting.value = false;
	}
}
</script>
