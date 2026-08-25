<template>
	<Dialog v-model="open" :options="{ title: `Restore · ${bench}`, size: 'xl' }">
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

					<p class="u-item-detail">
						Only files inside <span class="u-mono">{{ benchPath }}</span> can be used —
						copy the backup in with <span class="u-mono">scp</span> first. A path
						anywhere else on the server is refused.
					</p>
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
			<div class="flex justify-end gap-2">
				<Button @click="open = false">Cancel</Button>
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
import { backupsResource, restoreFilesResource, restoreSpaceResource, runRestoreResource } from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	benchPath: { type: String, default: "" },
	sites: { type: Array, default: () => [] },
	defaultSite: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started"]);

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
		encrypted: false,
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
	const match = name.match(/^\d{8}_\d{6}-(.+?)-database\.sql\.gz$/);
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
			description: `${f.directory} · ${f.modified}`,
			chip: f.size_text,
			chipClass: f.kind === kind ? "u-chip" : "u-chip-warn",
			keywords: `${f.kind} ${f.path}`,
		})),
	];
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
