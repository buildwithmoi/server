<template>
	<Dialog
		v-model="open"
		:options="{ title: `Restore · ${bench}`, size: 'xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<div class="flex flex-col gap-1.5">
					<span class="u-label">Site to restore</span>
					<SearchSelect
						v-model="site"
						:options="siteOptions"
						placeholder="Choose a site"
						search-placeholder="Search sites"
						empty-text="This bench has no sites."
					/>
				</div>

				<!--
					Two ways in, because there are two situations.

					A backup frappe wrote is one thing with four files, and picking
					it as a set is what stops you restoring Tuesday's database over
					Friday's files. A backup copied in from another server is three
					loose paths, and there is nothing to group them by.
				-->
				<div class="flex flex-col gap-1.5">
					<span class="u-label">Restore from</span>
					<div class="grid grid-cols-2 gap-2">
						<button
							v-for="option in SOURCES"
							:key="option.value"
							type="button"
							class="flex flex-col gap-1 rounded-md border px-3 py-2.5 text-left transition-colors duration-150"
							:class="
								source === option.value
									? 'border-[var(--ink)] bg-[var(--paper-sunk)]'
									: 'border-[var(--rule)] hover:border-[var(--rule-strong)]'
							"
							@click="source = option.value"
						>
							<span class="u-item-label">{{ option.label }}</span>
							<span class="u-item-detail">{{ option.hint }}</span>
						</button>
					</div>
				</div>

				<div v-if="source === 'Backup Set'" class="flex flex-col gap-1.5">
					<span class="u-label">Backup</span>
					<SearchSelect
						v-model="backup"
						:options="backupOptions"
						placeholder="Choose a backup"
						search-placeholder="Search by date"
						empty-text="No backups found for this bench."
						:loading="listing.loading"
					/>
					<p class="u-item-detail">
						Found in the site's backups folder and in the bench directory — copy a backup
						from another server into
						<span class="u-mono">{{ benchPath }}</span> and it shows up here.
					</p>
				</div>

				<!-- Three independent pickers. The database is required; the two
				     files tars are not, because plenty of backups are database
				     only and demanding all three would block them. -->
				<template v-else>
					<div v-for="slot in FILE_SLOTS" :key="slot.key" class="flex flex-col gap-1.5">
						<span class="u-label">
							{{ slot.label }}
							<span v-if="!slot.required" class="font-normal normal-case text-[var(--ink-ghost)]">
								· optional
							</span>
						</span>
						<SearchSelect
							v-model="picks[slot.key]"
							:options="optionsFor(slot.kind)"
							:placeholder="slot.placeholder"
							search-placeholder="Search by file name"
							empty-text="Nothing in the bench directory looks like this."
							:loading="files.loading"
							mono
						/>
					</div>

					<!--
						Upload, for a backup that is on your machine rather than the
						server. It streams straight into the bench's drop zone and
						then appears in the pickers above like anything else — so
						there is one restore path, not two.
					-->
					<div class="rounded-md border border-dashed border-[var(--rule-strong)] px-3 py-2.5">
						<div class="flex flex-wrap items-center gap-2.5">
							<Button :loading="uploading" :disabled="uploading" @click="pickFile">
								<template #prefix><Icon name="upload" :size="13" /></template>
								Upload from this computer
							</Button>
							<input
								ref="fileInput"
								type="file"
								class="hidden"
								accept=".sql,.gz,.tar,.tgz,.json"
								@change="onFilePicked"
							/>
							<span v-if="uploading" class="u-item-detail tabular-nums">
								{{ uploadName }} — {{ uploadPercent }}%
							</span>
							<span v-else class="u-item-detail">
								Or copy it in with <span class="u-mono">scp</span>; anything in
								<span class="u-mono">{{ benchPath }}</span> shows up here.
							</span>
						</div>

						<div v-if="uploading" class="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--paper-sunk)]">
							<div
								class="h-full rounded-full bg-[var(--ink)] transition-all duration-200"
								:style="{ width: `${Math.max(2, uploadPercent)}%` }"
							/>
						</div>

						<p class="u-item-detail mt-2">
							Keep the name frappe gave it — the timestamp and site in the filename are
							what group the dump with its files, and what warns you if it came from a
							different site.
						</p>
					</div>
				</template>

				<template v-if="chosen">
					<!-- What is actually in the set, and what will be replaced. -->
					<div class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2.5">
						<div class="flex items-start justify-between gap-3">
							<p class="u-item-label">{{ chosen.taken_at }}</p>
							<span class="u-chip shrink-0">{{ chosen.size_text }}</span>
						</div>
						<ul class="mt-1.5 flex flex-col gap-1">
							<li class="flex items-center gap-2">
								<Icon name="check" :size="12" class="u-ok shrink-0" />
								<span class="u-item-detail">Database</span>
							</li>
							<li v-if="chosen.public_files" class="flex items-center gap-2">
								<Icon name="check" :size="12" class="u-ok shrink-0" />
								<span class="u-item-detail">Public files</span>
							</li>
							<li v-if="chosen.private_files" class="flex items-center gap-2">
								<Icon name="check" :size="12" class="u-ok shrink-0" />
								<span class="u-item-detail">Private files</span>
							</li>
							<li v-if="!chosen.has_files" class="flex items-center gap-2">
								<Icon name="close" :size="12" class="shrink-0 text-[var(--ink-ghost)]" />
								<span class="u-item-detail">No files in this backup — database only.</span>
							</li>
						</ul>
					</div>

					<!-- The mistake most worth catching: right backup, wrong site. -->
					<div v-if="chosen.mismatch" class="u-note u-note-warn flex items-start gap-2.5">
						<Icon name="alert" :size="15" class="u-warn mt-0.5 shrink-0" />
						<p class="text-[12.5px] leading-relaxed">{{ chosen.mismatch }}</p>
					</div>

					<!--
						What the backup expects the bench to have.

						Restoring a database that references an app this bench does
						not have looks like it worked: the site comes up and every
						DocType belonging to the missing app is gone. It surfaces
						days later as import errors nobody connects to the restore.
						Read out of the dump itself, before anything is dropped.
					-->
					<div v-if="contents.loading" class="flex items-center gap-2 py-1">
						<Spinner class="h-3.5 w-3.5 text-[var(--ink-faint)]" />
						<span class="u-item-detail">Reading which apps this backup needs…</span>
					</div>

					<div
						v-else-if="needs"
						class="overflow-hidden rounded-md border"
						:class="missingApps.length ? 'border-[var(--danger-border)]' : 'border-[var(--rule)]'"
					>
						<header
							class="flex items-center justify-between gap-2 border-b px-3 py-2"
							:class="missingApps.length ? 'border-[var(--danger-border)] bg-[var(--danger-bg)]' : 'border-[var(--rule)]'"
						>
							<span class="u-item-label">
								{{ missingApps.length ? "This bench is missing apps this backup needs" : "Apps this backup needs" }}
							</span>
							<span v-if="needs.truncated" class="u-chip u-chip-warn shrink-0">partial read</span>
						</header>

						<ul v-if="needs.apps.length">
							<li
								v-for="app in needs.apps"
								:key="app.app_name"
								class="flex items-start gap-2.5 border-b border-[var(--rule)] px-3 py-2 last:border-b-0"
							>
								<Icon
									:name="app.present ? (app.branch_matches ? 'check' : 'alert') : 'close'"
									:size="13"
									class="mt-0.5 shrink-0"
									:class="app.present ? (app.branch_matches ? 'u-ok' : 'u-warn') : 'u-danger'"
								/>
								<span class="min-w-0 flex-1">
									<span class="u-item-label u-mono block">{{ app.app_name }}</span>
									<span class="u-item-detail block">{{ app.note }}</span>
								</span>
								<Button
									v-if="!app.present"
									size="sm"
									class="shrink-0"
									@click="getApp(app)"
								>Get it</Button>
								<span class="u-item-detail shrink-0 tabular-nums">
									{{ app.git_branch || "—" }}
								</span>
								<span class="u-chip shrink-0">v{{ app.app_version || "?" }}</span>
							</li>
						</ul>

						<p v-if="needs.error" class="u-item-detail px-3 py-2.5">{{ needs.error }}</p>
					</div>

					<div v-if="missingApps.length" class="u-note u-note-danger flex flex-col gap-2">
						<div class="flex items-start gap-2.5">
							<Icon name="alert" :size="15" class="u-danger mt-0.5 shrink-0" />
							<p class="text-[12.5px] leading-relaxed">
								Clone
								<span class="u-mono">{{ missingApps.join(", ") }}</span>
								onto this bench first. Restoring without them looks like it worked —
								the site comes up and everything those apps owned is gone.
							</p>
						</div>
						<label class="flex cursor-pointer items-center gap-2.5">
							<input v-model="ignoreMissing" type="checkbox" />
							<span class="u-item-detail">
								Restore anyway — I will install them straight afterwards.
							</span>
						</label>
					</div>

					<!-- Disk space. A restore that fills the disk leaves a
					     half-loaded database behind and takes the whole server
					     with it — every other site on this bench included. -->
					<div
						v-if="space"
						class="flex items-start gap-2.5"
						:class="space.enough ? 'u-note' : 'u-note u-note-danger'"
					>
						<Icon
							:name="space.enough ? 'database' : 'alert'"
							:size="15"
							class="mt-0.5 shrink-0"
							:class="space.enough ? 'text-[var(--ink-faint)]' : 'u-danger'"
						/>
						<p class="text-[12.5px] leading-relaxed">{{ space.detail }}</p>
					</div>

					<label
						v-if="space && !space.enough"
						class="flex cursor-pointer items-start gap-2.5 rounded-md border border-[var(--danger-border)] px-3 py-2.5"
					>
						<input v-model="ignoreSpace" type="checkbox" class="mt-[3px]" />
						<span class="u-item-detail">
							Restore anyway. The estimate is deliberately pessimistic and yours may
							well fit — but if it does not, the disk fills and every site on this
							bench goes down with it.
						</span>
					</label>

					<div v-if="chosen.has_files" class="flex flex-col gap-2">
						<span class="u-label">Also restore</span>
						<label v-if="chosen.public_files" class="flex cursor-pointer items-center gap-2.5">
							<input v-model="withPublic" type="checkbox" />
							<span class="u-item-detail">Public files</span>
						</label>
						<label v-if="chosen.private_files" class="flex cursor-pointer items-center gap-2.5">
							<input v-model="withPrivate" type="checkbox" />
							<span class="u-item-detail">Private files</span>
						</label>
					</div>

					<div class="flex flex-col gap-1.5">
						<span class="u-label">Database root password</span>
						<input
							v-model="dbPassword"
							type="password"
							autocomplete="new-password"
							placeholder="required"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						/>
						<p class="u-item-detail">
							Needed to drop and recreate the database. Stored encrypted, cleared the
							moment the job finishes, and kept out of the logged command.
						</p>
					</div>

					<div v-if="chosen.encrypted" class="flex flex-col gap-1.5">
						<span class="u-label">Backup encryption key</span>
						<input
							v-model="encryptionKey"
							type="password"
							autocomplete="new-password"
							placeholder="required — this backup is encrypted"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						/>
						<p class="u-item-detail">
							The <span class="u-mono">encryption_key</span> from the site config on the
							server this backup came from.
						</p>
					</div>

					<label
						class="flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2.5"
						:class="backupFirst ? 'u-note u-note-ok' : 'u-note u-note-danger'"
					>
						<input v-model="backupFirst" type="checkbox" class="mt-[3px]" />
						<span class="min-w-0">
							<span class="u-item-label">Back up {{ siteName }} first</span>
							<span class="u-item-detail mt-0.5 block">
								{{
									backupFirst
										? "Runs bench backup before anything is replaced. If that backup fails, nothing is restored."
										: "Nothing will be saved. If this restore is wrong, the current data is gone for good."
								}}
							</span>
						</span>
					</label>

					<!-- Typing the site name, for the same reason drop-site asks:
					     a checkbox is something you tick without reading. -->
					<div class="u-note u-note-danger flex flex-col gap-2">
						<div class="flex items-start gap-2.5">
							<Icon name="alert" :size="15" class="u-danger mt-0.5 shrink-0" />
							<p class="text-[12.5px] leading-relaxed">
								This replaces everything in
								<span class="font-medium">{{ siteName }}</span> and cannot be undone.
								Type the site name to confirm.
							</p>
						</div>
						<input
							v-model.trim="confirm"
							:placeholder="siteName"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						/>
					</div>

					<div class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2.5">
						<p class="u-mono break-all text-[11.5px] text-[var(--ink-faint)]">
							<template v-if="backupFirst">$ {{ backupPreview }}<br /></template>
							$ {{ preview }}
						</p>
					</div>
				</template>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="u-danger mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex items-center justify-end gap-2">
				<!-- Said out loud while it is happening. The work lives in this
				     dialog, so closing it throws the work away — and there is no
				     job card to come back to the way there is for a bench
				     command. -->
				<span v-if="busy" class="u-item-detail mr-auto flex items-center gap-2">
					<Spinner class="h-3.5 w-3.5" />
					{{ busyLabel }}
				</span>
				<Button :disabled="busy" @click="open = false">Cancel</Button>
				<Button variant="solid" :loading="running" :disabled="!canRun" @click="run">
					Restore
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
import { useBusyGuard } from "../busy";
import {
	backupsResource,
	inspectBackupResource,
	restoreFilesResource,
	restoreSpaceResource,
	runRestoreResource,
	uploadBackup,
} from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	benchPath: { type: String, default: "" },
	sites: { type: Array, default: () => [] },
	defaultSite: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started", "install-app"]);

const SOURCES = [
	{
		value: "Backup Set",
		label: "A backup on this bench",
		hint: "One backup frappe wrote, with its files already matched to its dump.",
	},
	{
		value: "Chosen Files",
		label: "Choose the files myself",
		hint: "For a backup copied in from another server, or files from different backups.",
	},
];

const FILE_SLOTS = [
	{
		key: "database",
		kind: "database",
		label: "Database dump",
		required: true,
		placeholder: "Choose the .sql.gz dump",
	},
	{ key: "public", kind: "public", label: "Public files tar", required: false, placeholder: "None" },
	{ key: "private", kind: "private", label: "Private files tar", required: false, placeholder: "None" },
];

const listing = backupsResource();
const files = restoreFilesResource();
const spaceCheck = restoreSpaceResource();
const contents = inspectBackupResource();
const fileInput = ref(null);
const uploading = ref(false);
const uploadPercent = ref(0);
const uploadName = ref("");
const ignoreMissing = ref(false);
const source = ref("Backup Set");
const picks = ref({ database: null, public: null, private: null });
const ignoreSpace = ref(false);
const site = ref(null);
const backup = ref(null);
const withPublic = ref(false);
const withPrivate = ref(false);
const backupFirst = ref(true);
const dbPassword = ref("");
const encryptionKey = ref("");
const confirm = ref("");
const running = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

/**
 * Work that would be lost if the dialog closed now.
 *
 * The upload and the queueing are the expensive ones; reading a dump for the
 * apps it needs can take a while on a large backup and is just as annoying to
 * restart. Listing files is cheap and deliberately not included — blocking on
 * every fetch would make the dialog feel stuck.
 */
const busy = computed(
	() => uploading.value || running.value || contents.loading || spaceCheck.loading,
);
const busyLabel = computed(() => {
	if (uploading.value) return `Uploading ${uploadName.value} — ${uploadPercent.value}%`;
	if (running.value) return "Starting the restore…";
	if (contents.loading) return "Reading which apps this backup needs…";
	return "Checking disk space…";
});
useBusyGuard(busy);

const siteName = computed(() => site.value?.value || "");
const siteOptions = computed(() =>
	props.sites.map((s) => ({
		label: s,
		value: s,
		description: s === props.defaultSite ? "Default site for this bench" : "",
	})),
);

const backups = computed(() => listing.data?.backups || []);

/**
 * The backup being restored, whichever way it was chosen.
 *
 * Both sources produce the same shape so everything downstream — the contents
 * list, the mismatch warning, the preview, the space check — has one thing to
 * read rather than two.
 */
const chosen = computed(() => {
	if (source.value === "Backup Set") {
		return backups.value.find((b) => b.key === backup.value?.value) || null;
	}
	const database = picks.value.database?.value;
	if (!database) return null;
	const pick = (key) => picks.value[key]?.value || null;
	const named = (path) => (path ? path.split("/").pop() : null);
	return {
		key: `chosen:${named(database)}`,
		taken_at: fileFor(database)?.modified || "chosen by hand",
		database,
		public_files: pick("public"),
		private_files: pick("private"),
		has_files: Boolean(pick("public") || pick("private")),
		size_text: chosenSizeText.value,
		// The real flag, read from disk. It used to be hardcoded false, so the
		// encryption-key field never appeared and an encrypted dump copied in
		// from another server — the exact case this mode exists for — could be
		// selected, previewed and submitted, only to be refused by the server
		// with no way in the interface to satisfy it.
		encrypted: Boolean(fileFor(database)?.encrypted),
		mismatch: chosenMismatch.value,
		source: "chosen",
	};
});

const candidates = computed(() => files.data?.files || []);
const fileFor = (path) => candidates.value.find((f) => f.path === path);

const chosenSizeText = computed(() => {
	const total = ["database", "public", "private"]
		.map((k) => fileFor(picks.value[k]?.value)?.size || 0)
		.reduce((a, b) => a + b, 0);
	if (!total) return "";
	const units = ["B", "KB", "MB", "GB"];
	let value = total;
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
});

/** The same right-backup-wrong-site check, applied to a hand-picked dump. */
const chosenMismatch = computed(() => {
	const name = picks.value.database?.value?.split("/").pop() || "";
	// Mirrors restore.BACKUP_NAME, including the -enc and -partial markers.
	// Without them this silently stopped firing for encrypted backups — the
	// case where restoring the wrong site's data is least recoverable.
	const match = name.match(/^\d{8}_\d{6}-(.+?)(?:-partial)?-database(?:-enc)?\.sql\.gz$/);
	if (!match) return "";
	const from = match[1].replace(/_/g, ".");
	if (from === siteName.value) return "";
	return `This dump is from ${from}, not ${siteName.value}. Restoring it will replace this site's data with that site's data.`;
});

function optionsFor(kind) {
	const ordered = [
		...candidates.value.filter((f) => f.kind === kind),
		...candidates.value.filter((f) => f.kind !== kind),
	];
	return [
		...(kind === "database" ? [] : [{ label: "None", value: "", description: "Do not restore these." }]),
		...ordered.map((f) => ({
			label: f.name,
			value: f.path,
			description: [
				`${f.directory} · ${f.modified}`,
				f.encrypted ? "Encrypted — needs its key." : "",
			]
				.filter(Boolean)
				.join(" · "),
			chip: f.encrypted ? "encrypted" : f.size_text,
			chipClass: f.encrypted ? "u-chip-warn" : f.kind === kind ? "u-chip" : "u-chip-warn",
			keywords: `${f.kind} ${f.path} ${f.encrypted ? "encrypted" : ""}`,
		})),
	];
}

const needs = computed(() => contents.data || null);
const missingApps = computed(() => needs.value?.missing || []);

/**
 * Hand the app off to the install dialog, with its branch already filled in.
 *
 * The restore stays open behind it: the operator is part way through a form
 * they will come back to, and losing the site, the dump and the typed
 * confirmation to fetch a missing app would make the check more annoying than
 * the failure it prevents.
 */
function getApp(app) {
	emit("install-app", { repo: app.app_name, branch: app.git_branch || "" });
}

function pickFile() {
	fileInput.value?.click();
}

async function onFilePicked(event) {
	const file = event.target.files?.[0];
	event.target.value = "";
	if (!file) return;

	uploading.value = true;
	uploadPercent.value = 0;
	uploadName.value = file.name;
	error.value = "";
	try {
		const result = await uploadBackup(props.bench, file, (percent) => {
			uploadPercent.value = percent;
		});
		toast.success(`${result.name} uploaded (${result.size_text})`);
		// Re-read both listings so the new file appears in the pickers, then
		// select it, because selecting it is obviously what was meant.
		await Promise.all([
			listing.fetch({ bench: props.bench, site: siteName.value }),
			files.fetch({ bench: props.bench, site: siteName.value }),
		]);
		const uploaded = candidates.value.find((f) => f.path === result.path);
		if (uploaded && uploaded.kind === "database") {
			picks.value = { ...picks.value, database: { label: uploaded.name, value: uploaded.path } };
		}
	} catch (err) {
		error.value = err.message || "The upload failed";
	} finally {
		uploading.value = false;
	}
}

/** Disk headroom: read from the backup set, or asked for explicitly. */
const space = computed(() => {
	if (source.value === "Backup Set") return chosen.value?.space || null;
	return spaceCheck.data || null;
});

const backupOptions = computed(() =>
	backups.value.map((b) => ({
		label: b.taken_at,
		value: b.key,
		description: [
			b.has_files ? "database and files" : "database only",
			b.source === "bench" ? "copied into the bench directory" : "",
			b.mismatch ? `from ${b.site_slug.replace(/_/g, ".")}` : "",
		]
			.filter(Boolean)
			.join(" · "),
		chip: b.size_text,
		chipClass: b.mismatch ? "u-chip-warn" : "u-chip",
		keywords: `${b.key} ${b.site_slug} ${b.encrypted ? "encrypted" : ""}`,
	})),
);

const backupPreview = computed(
	() =>
		`bench --site ${siteName.value} backup${
			withPublic.value || withPrivate.value ? " --with-files" : ""
		}`,
);

const preview = computed(() => {
	if (!chosen.value) return "";
	let out = `bench --site ${siteName.value} restore ${chosen.value.database} --db-root-password ********`;
	if (chosen.value.encrypted) out += " --encryption-key ********";
	if (withPublic.value && chosen.value.public_files)
		out += ` --with-public-files ${chosen.value.public_files}`;
	if (withPrivate.value && chosen.value.private_files)
		out += ` --with-private-files ${chosen.value.private_files}`;
	return out;
});

const canRun = computed(() => {
	if (!chosen.value || !siteName.value) return false;
	if (!dbPassword.value) return false;
	if (chosen.value.encrypted && !encryptionKey.value) return false;
	if (space.value && !space.value.enough && !ignoreSpace.value) return false;
	// Missing apps are the failure that looks like a success, so they block by
	// default — but the operator can say they will install them next.
	if (missingApps.value.length && !ignoreMissing.value) return false;
	return confirm.value === siteName.value;
});

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) {
			// Never leave credentials sitting in a closed dialog.
			dbPassword.value = "";
			encryptionKey.value = "";
			confirm.value = "";
			ignoreMissing.value = false;
			return;
		}
		error.value = "";
		if (!site.value) {
			const preferred = props.defaultSite || props.sites[0];
			if (preferred) site.value = { label: preferred, value: preferred };
		}
	},
);

// Backups are per-site, so the list follows the site rather than being fetched
// once — picking a different site must not leave the previous site's backups on
// screen looking selectable.
watch(
	[site, () => props.modelValue],
	([value, isOpen]) => {
		if (!isOpen || !value?.value) return;
		backup.value = null;
		picks.value = { database: null, public: null, private: null };
		listing.fetch({ bench: props.bench, site: value.value });
		files.fetch({ bench: props.bench, site: value.value });
	},
	{ immediate: true },
);

// Hand-picked files have no pre-computed sizes, so the space check has to be
// asked for each time the selection changes.
watch(
	() => [source.value, picks.value.database?.value, picks.value.public?.value, picks.value.private?.value],
	([mode, database, publicFile, privateFile]) => {
		ignoreSpace.value = false;
		if (mode !== "Chosen Files" || !database) return;
		spaceCheck.fetch({
			bench: props.bench,
			site: siteName.value,
			database_file: database,
			public_file: publicFile || null,
			private_file: privateFile || null,
		});
	},
);

watch(source, () => {
	confirm.value = "";
	ignoreSpace.value = false;
});

watch(chosen, (value) => {
	// Default to restoring whatever the backup actually contains: if someone
	// took a backup with files, they meant to be able to put the files back.
	withPublic.value = Boolean(value?.public_files);
	withPrivate.value = Boolean(value?.private_files);
});

watch([() => picks.value.database, backup], () => (ignoreSpace.value = false));

// Read the dump for the apps it expects, whenever the selection changes. An
// encrypted dump cannot be read without its key, and says so rather than
// silently reporting no apps.
watch(
	[chosen, () => props.modelValue],
	([value, isOpen]) => {
		ignoreMissing.value = false;
		if (!isOpen || !value?.database || !siteName.value) return;
		contents.fetch(
			source.value === "Backup Set"
				? { bench: props.bench, site: siteName.value, backup_key: backup.value?.value }
				: { bench: props.bench, site: siteName.value, database_file: value.database },
		);
	},
	{ immediate: true },
);

async function run() {
	running.value = true;
	error.value = "";
	try {
		const result = await runRestoreResource().submit({
			bench: props.bench,
			site: siteName.value,
			source: source.value,
			backup_key: source.value === "Backup Set" ? backup.value?.value : null,
			database_file: picks.value.database?.value || null,
			public_file: picks.value.public?.value || null,
			private_file: picks.value.private?.value || null,
			db_root_password: dbPassword.value,
			encryption_key: encryptionKey.value || null,
			with_public_files: withPublic.value ? 1 : 0,
			with_private_files: withPrivate.value ? 1 : 0,
			backup_first: backupFirst.value ? 1 : 0,
			confirm: confirm.value,
		});
		watchJob(result.name, {
			operation: "Restore",
			app_name: `Restore · ${siteName.value}`,
			bench: props.bench,
			status: "Queued",
		});
		toast.success(`Restoring ${siteName.value}`);
		open.value = false;
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the restore";
	} finally {
		running.value = false;
		dbPassword.value = "";
		encryptionKey.value = "";
	}
}
</script>
