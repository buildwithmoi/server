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
					<SearchSelect
						v-model="repo"
						:options="repoOptions"
						placeholder="Choose a repository"
						search-placeholder="Search repositories"
						empty-text="No repository matches that."
						:loading="reposRes.loading"
						mono
					/>
					<p v-if="!repoOptions.length && !reposRes.loading" class="text-[11.5px] text-[var(--ink-faint)]">
						Nothing cached for this account yet — use “re-sync list”.
					</p>
				</div>

				<!-- Cloning over an app that is already here is the one case where
				     the obvious action is probably the wrong one, so say so and
				     offer the other one rather than letting the pre-flight refuse
				     it after the job has been queued. -->
				<div
					v-if="installedApp"
					class="flex items-start gap-2.5 rounded-md border border-[var(--ink)] bg-[var(--paper-sunk)] px-3 py-2.5"
				>
					<Icon name="alert" :size="15" class="mt-0.5 shrink-0" />
					<div class="min-w-0 flex-1">
						<p class="text-[12.5px] leading-relaxed">
							<span class="u-mono">{{ installedApp.app_name }}</span> is already in
							<span class="u-mono">{{ bench }}</span> on
							<span class="u-mono">{{ installedApp.branch }}</span>, so the branch below is
							pre-selected to match rather than defaulting to the repository's
							<span class="u-mono">{{ repoDefaultBranch || "default" }}</span>.
						</p>
						<p class="mt-1 text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							Cloning again needs “Overwrite if already present”, which archives the
							current copy to archived/apps/ rather than deleting it.
						</p>
						<button
							type="button"
							class="mt-1.5 text-[12px] underline underline-offset-2"
							@click="switchToPull"
						>Update it in place instead →</button>
					</div>
				</div>

				<div v-if="repo" class="flex flex-col gap-1.5">
					<!-- The failure notice sits ABOVE the field on purpose. Below it,
					     an open dropdown covers it and the only thing visible is
					     "No results found", which blames the search instead of
					     naming the actual problem. -->
					<div
						v-if="branchError"
						class="flex items-start gap-2.5 rounded-md border border-[var(--ink)] bg-[var(--paper-sunk)] px-3 py-2.5"
					>
						<Icon name="alert" :size="15" class="mt-0.5 shrink-0" />
						<div class="min-w-0">
							<p class="text-[12.5px] leading-relaxed">{{ branchError }}</p>
							<RouterLink
								v-if="/token/i.test(branchError)"
								:to="{ name: 'GitHubProfiles' }"
								class="mt-1 inline-block text-[12px] underline underline-offset-2"
								@click="open = false"
							>Add an access token</RouterLink>
							<p class="mt-1 text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								You can still type the branch name below.
							</p>
						</div>
					</div>

					<div class="flex items-baseline justify-between">
						<span class="u-label">Branch</span>
						<div class="flex items-center gap-3">
							<button
								v-if="preferredBranch && branchValue !== preferredBranch"
								type="button"
								class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
								@click="resetBranch"
							>
								use {{ branchSource === "installed" ? "installed" : "default" }}
								({{ preferredBranch }})
							</button>
							<button
								v-if="branchOptions.length"
								type="button"
								class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
								@click="manualBranch = !manualBranch"
							>{{ manualBranch ? "pick from list" : "type a name" }}</button>
						</div>
					</div>

					<!-- A picker that can only offer what it managed to fetch is a
					     dead end when the fetch fails, and a select accepts nothing
					     but its own options. So a typed name is always reachable,
					     and becomes the default when there is no list to pick. -->
					<input
						v-if="manualBranch || (!branchOptions.length && !branchesRes.loading)"
						v-model.trim="typedBranch"
						:placeholder="preferredBranch || 'branch name'"
						class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
					/>
					<SearchSelect
						v-else
						v-model="branch"
						:options="branchOptions"
						:placeholder="branchesRes.loading ? 'Loading branches…' : 'Default branch'"
						search-placeholder="Search branches"
						empty-text="No branch matches that."
						:loading="branchesRes.loading"
						mono
					/>

					<p v-if="branchesRes.loading" class="text-[11.5px] text-[var(--ink-faint)]">
						Default branch selected. Loading the full branch list…
					</p>
					<p
						v-else-if="installedBranchMissing"
						class="text-[11.5px] leading-relaxed text-[var(--ink)]"
					>
						<span class="u-mono">{{ installedApp.branch }}</span> is the branch in this bench
						but no longer exists on the remote — it may have been renamed or deleted after a
						merge. Pick another, or the clone will fail on it.
					</p>
					<p v-else-if="branchOptions.length" class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						<template v-if="branchSource === 'installed'">
							Pre-selected to match this bench.
						</template>
						<template v-else>
							Leave blank to use the repository default.
						</template>
						{{ branchOptions.length }} branches available.
						<span v-if="branchesRes.data?.truncated">
							Only the first {{ branchOptions.length }} are listed — use “type a name” for
							anything beyond that.
						</span>
					</p>
					<p v-else-if="!branchError" class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						No branch list available. Type a name, or leave blank for the repository default.
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
					<SearchSelect
						v-model="app"
						:options="appOptions"
						placeholder="Choose an app"
						search-placeholder="Search apps in this bench"
						empty-text="No app matches that."
						:loading="appsRes.loading"
						mono
					/>
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
import { Button, Dialog, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { watchJob } from "../jobs";
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
	/**
	 * Repository and branch to start from, when opened from somewhere that
	 * already knows them — the restore dialog naming an app the backup needs.
	 * The account is still chosen by hand; only the operator knows which one
	 * holds it.
	 */
	prefill: { type: Object, default: null },
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
const manualBranch = ref(false);
const typedBranch = ref("");
const submitting = ref(false);
const syncing = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (value) => emit("update:modelValue", value),
});

const verb = computed(() => (operation.value === "Pull" ? "Pull" : "Clone"));
const profiles = computed(() => profilesRes.data || []);
const repoDefaultBranch = computed(
	() => repo.value?.defaultBranch || branchesRes.data?.default_branch || "",
);
const branchError = computed(() => branchesRes.data?.error || "");

/**
 * The app in THIS bench that the selected repository corresponds to, if any.
 *
 * The repository name is the app directory name — that is how `derive_app_name`
 * builds it — so the match is direct.
 */
const installedApp = computed(() => {
	const name = repo.value?.value;
	return name ? (appsRes.data || []).find((a) => a.app_name === name) || null : null;
});

/**
 * What the branch field should start on.
 *
 * WHY THE INSTALLED BRANCH WINS OVER THE REPOSITORY DEFAULT. Re-cloning an app
 * that is already in a bench almost always means matching what is there —
 * fb-15-1 runs erpnext on version-15, and offering `develop` because that is
 * what GitHub calls default would quietly replace a working checkout with a
 * different major version. The repository default is the right answer only for
 * an app the bench has never seen.
 */
const preferredBranch = computed(
	() => installedApp.value?.branch || repoDefaultBranch.value || "",
);

/** Whether the pre-selected branch came from the bench or from GitHub. */
const branchSource = computed(() =>
	installedApp.value?.branch ? "installed" : repoDefaultBranch.value ? "repository" : "",
);

/**
 * The installed branch may no longer exist upstream — renamed, or deleted after
 * a merge. Worth saying, because the clone would fail on it minutes later.
 */
const installedBranchMissing = computed(() => {
	const wanted = installedApp.value?.branch;
	if (!wanted || !branchOptions.value.length) return false;
	return !branchOptions.value.some((b) => b.value === wanted);
});

/**
 * The chosen branch, from whichever control is showing.
 *
 * Two controls can set this — the picker and the free-text box — and every
 * other piece of logic wants one answer, not a branch of its own.
 */
const branchValue = computed(() =>
	manualBranch.value || !branchOptions.value.length ? typedBranch.value : branch.value?.value || "",
);

const repoOptions = computed(() =>
	(reposRes.data || []).map((r) => ({
		label: r.repo_name,
		value: r.repo_name,
		defaultBranch: r.default_branch,
		description: r.description || "",
		chip: r.is_archived ? "archived" : r.is_private ? "private" : "public",
		chipClass: r.is_archived ? "u-chip-warn" : "u-chip",
		keywords: r.default_branch || "",
	})),
);

const branchOptions = computed(() =>
	(branchesRes.data?.branches || []).map((b) => ({
		label: b.name,
		value: b.name,
		description:
			b.name === installedApp.value?.branch
				? "in this bench"
				: b.name === repoDefaultBranch.value
					? "repository default"
					: b.protected
						? "protected"
						: "",
	})),
);

const appOptions = computed(() =>
	(appsRes.data || []).map((a) => ({
		label: a.app_name,
		value: a.app_name,
		description: a.branch || "",
		chip: a.is_dirty ? "uncommitted" : "",
		chipClass: "u-chip-warn",
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
		// Applied before the repository list loads, so the branch survives the
		// profile watcher that clears both when an account is chosen.
		wanted.value = props.prefill ? { ...props.prefill } : null;
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

/** A repository/branch we were asked to start from, until it is applied. */
const wanted = ref(null);

watch(profile, (value) => {
	repo.value = null;
	branch.value = null;
	if (value) reposRes.submit({ profile: value });
});

// Once an account's repositories arrive, select the one we were sent looking
// for. Matched by name rather than assumed to exist: an app in a backup may
// simply not be in the account that was picked, and saying nothing would be
// better than selecting the wrong repository.
watch(
	() => reposRes.data,
	(repos) => {
		const target = wanted.value;
		if (!target || !repos?.length) return;
		const match = repos.find((r) => r.name === target.repo || r.repo === target.repo);
		if (!match) return;
		repo.value = { label: match.name || match.repo, value: match.name || match.repo };
		if (target.branch) branch.value = { label: target.branch, value: target.branch };
		wanted.value = null;
	},
);

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

	manualBranch.value = false;
	// preferredBranch already knows about the bench, so this is correct before
	// the branch list has loaded and stays correct afterwards.
	if (preferredBranch.value) {
		setBranch(preferredBranch.value);
	}
	await branchesRes.submit({ profile: profile.value, repo: value.value });
	if (!branch.value && preferredBranch.value) {
		setBranch(preferredBranch.value);
	}
});

/** Jump to the Pull tab with the app already chosen. */
function switchToPull() {
	const name = installedApp.value?.app_name;
	operation.value = "Pull";
	if (name) app.value = { label: name, value: name };
}

function setBranch(name) {
	branch.value = name ? { label: name, value: name } : null;
	typedBranch.value = name || "";
}

function resetBranch() {
	setBranch(preferredBranch.value);
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
						branch: branchValue.value || null, install_on_site: site.value || null,
						skip_assets: skipAssets.value, overwrite_existing: overwrite.value,
					};
		const result = await createInstallResource().submit({ ...payload, run: true });

		// Hand it to the dock rather than navigating anywhere. The whole reason
		// to background a clone is to carry on doing something else, and moving
		// the user to another page defeats that.
		watchJob(result.name, {
			operation: operation.value,
			app_name: operation.value === "Pull" ? app.value.value : repo.value.value,
			bench: props.bench,
			branch: operation.value === "Pull" ? pullBranch.value || null : branchValue.value || null,
			status: "Queued",
		});
		toast.success(`${result.name} started`);
		open.value = false;
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the operation";
	} finally {
		submitting.value = false;
	}
}
</script>
