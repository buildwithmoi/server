<template>
	<Dialog
		v-model="open"
		:options="{ title: `SSL · ${bench}`, size: 'xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<!--
					Readiness first, before the choice of operation.

					Every one of these is a reason SSL will not work on this box, and
					all three are cheap to check. Showing them up front turns a
					three-minute failure — one of which stops nginx on the way — into
					a sentence read before anything runs.
				-->
				<div v-if="readiness.loading" class="flex items-center gap-2 py-1">
					<Spinner class="h-3.5 w-3.5 text-[var(--ink-faint)]" />
					<span class="u-item-detail">Checking this server…</span>
				</div>

				<div
					v-else-if="report"
					class="rounded-md border px-3 py-2.5"
					:class="report.ready ? 'u-note u-note-ok' : 'u-note u-note-warn'"
				>
					<div class="flex items-start gap-2.5">
						<Icon
							:name="report.ready ? 'check' : 'alert'"
							:size="15"
							class="mt-0.5 shrink-0"
							:class="report.ready ? 'u-ok' : 'u-warn'"
						/>
						<div class="min-w-0 flex-1">
							<p class="u-item-label">
								{{ report.ready ? "This server can issue certificates." : "Not ready yet." }}
							</p>
							<ul class="mt-1.5 flex flex-col gap-1">
								<li
									v-for="check in report.checks"
									:key="check.key"
									class="flex items-start gap-2"
								>
									<Icon
										:name="check.ok ? 'check' : 'close'"
										:size="12"
										class="mt-[3px] shrink-0"
										:class="check.ok ? 'u-ok' : 'u-danger'"
									/>
									<span class="u-item-detail">
										<span class="u-item-label">{{ check.label }}</span>
										<template v-if="!check.ok"> — {{ check.detail }}</template>
									</span>
								</li>
							</ul>
						</div>
					</div>
				</div>

				<!-- The two certbot operations. Laid out as cards rather than a
				     select: they do different things to a live server, and the
				     difference should be readable without opening a menu. -->
				<div class="flex flex-col gap-1.5">
					<span class="u-label">What do you want to do</span>
					<div class="grid grid-cols-2 gap-2">
						<button
							v-for="option in MODES"
							:key="option.value"
							type="button"
							class="flex flex-col gap-1 rounded-md border px-3 py-2.5 text-left transition-colors duration-150"
							:class="
								mode === option.value
									? 'border-[var(--ink)] bg-[var(--paper-sunk)]'
									: 'border-[var(--rule)] hover:border-[var(--rule-strong)]'
							"
							@click="mode = option.value"
						>
							<span class="u-item-label">{{ option.label }}</span>
							<span class="u-item-detail">{{ option.hint }}</span>
						</button>
					</div>
				</div>

				<!-- Issuing is per-site; renewing is not. certbot renews every
				     certificate on the box in one pass, and pretending otherwise
				     by showing a site picker would be a lie about what runs. -->
				<template v-if="mode === 'issue'">
					<div class="flex flex-col gap-1.5">
						<span class="u-label">Site</span>
						<SearchSelect
							v-model="picked"
							:options="siteOptions"
							placeholder="Choose a site"
							search-placeholder="Search sites"
							empty-text="This bench has no sites."
							:loading="readiness.loading"
						/>
						<p v-if="selectedSite" class="u-item-detail">{{ selectedSite.note }}</p>
					</div>

					<!-- DNS, checked before certbot is asked. Let's Encrypt
					     rate-limits failed authorisations per account and the block
					     outlasts the mistake, so this is the cheapest check in the
					     dialog and the most expensive one to skip. -->
					<div
						v-if="dns"
						class="flex items-start gap-2.5"
						:class="dns.level === 'ok' ? 'u-note u-note-ok' : dns.level === 'warn' ? 'u-note u-note-warn' : 'u-note u-note-danger'"
					>
						<Icon
							:name="dns.level === 'ok' ? 'check' : 'alert'"
							:size="15"
							class="mt-0.5 shrink-0"
							:class="dns.level === 'ok' ? 'u-ok' : dns.level === 'warn' ? 'u-warn' : 'u-danger'"
						/>
						<p class="text-[12.5px] leading-relaxed">{{ dns.detail }}</p>
					</div>

					<div v-if="selectedSite?.custom_domains?.length" class="flex flex-col gap-1.5">
						<span class="u-label">Domain</span>
						<SearchSelect
							v-model="domain"
							:options="domainOptions"
							placeholder="The site's own domain"
							search-placeholder="Search domains"
							mono
						/>
						<p class="u-item-detail">
							bench will only certify a domain the site already knows about. Add others
							with <span class="u-mono">bench setup add-domain</span> first.
						</p>
					</div>
				</template>

				<label
					v-else
					class="flex cursor-pointer items-start gap-2.5 rounded-md border border-[var(--rule)] px-3 py-2.5"
				>
					<input v-model="dryRun" type="checkbox" class="mt-[3px]" />
					<span class="min-w-0">
						<span class="u-item-label">Rehearse first (dry run)</span>
						<span class="u-item-detail mt-0.5 block">
							Runs against Let's Encrypt's staging server. Nothing is installed. Worth
							doing: Let's Encrypt rate-limits failures per IP address, and the block
							outlasts the mistake.
						</span>
					</span>
				</label>

				<!-- Exactly what will run, and what it does to a live server. -->
				<div class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2.5">
					<p class="u-item-detail">{{ summary }}</p>
					<p class="u-mono mt-2 break-all text-[11.5px] text-[var(--ink-faint)]">
						$ {{ preview }}
					</p>
				</div>

				<!--
					Both modes stop nginx, including the rehearsal.

					The renewal argv carries --pre-hook "systemctl stop nginx", and
					--dry-run does not change that — certbot still runs the hooks.
					Warning only on "issue" told the operator a rehearsal was free
					when it takes every site on the machine offline for the length
					of the check.
				-->
				<div class="u-note u-note-warn flex items-start gap-2.5">
					<Icon name="alert" :size="15" class="u-warn mt-0.5 shrink-0" />
					<p class="text-[12.5px] leading-relaxed">
						<template v-if="mode === 'issue'">
							nginx stops while certbot holds port 443, so every site on this bench is
							briefly offline. The domain must already point at this server.
						</template>
						<template v-else>
							nginx stops for the check and starts again afterwards, so every site on
							this machine is briefly offline — a rehearsal included, because certbot
							runs the same hooks either way.
						</template>
					</p>
				</div>

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
					{{ mode === "issue" ? "Issue certificate" : dryRun ? "Rehearse renewal" : "Renew" }}
				</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { watchJob } from "../jobs";
import { useBusyGuard } from "../busy";
import { runSslResource, sslReadinessResource } from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
});
const emit = defineEmits(["update:modelValue", "started"]);

const MODES = [
	{
		value: "issue",
		label: "Issue or reinstall",
		hint: "Get a new certificate for one site, or replace a broken one.",
	},
	{
		value: "renew",
		label: "Renew",
		hint: "Refresh every certificate already on this server.",
	},
];

const readiness = sslReadinessResource();
const mode = ref("issue");
const picked = ref(null);
const domain = ref(null);
const dryRun = ref(true);
const running = ref(false);
const error = ref("");

// Closing mid-flight loses the work — the dialog owns it, and there is no
// job card to come back to. See busy.ts.
const busy = computed(() => running.value);
useBusyGuard(busy);

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

const report = computed(() => readiness.data || null);
const sites = computed(() => report.value?.sites || []);

/**
 * Certificate state is the chip, because it is the reason you opened this.
 * "Expires in 9 days" is the difference between a routine job and an urgent one.
 */
const siteOptions = computed(() =>
	sites.value.map((s) => ({
		label: s.site,
		value: s.site,
		description: s.note,
		chip: s.has_cert ? (s.days_left != null ? `${s.days_left}d` : "has cert") : "no cert",
		chipClass: chipFor(s),
		keywords: `${s.domain} ${s.custom_domains.join(" ")}`,
	})),
);

function chipFor(site) {
	if (!site.has_cert) return "u-chip-warn";
	if (site.days_left == null) return "u-chip";
	if (site.days_left <= 0) return "u-chip-danger";
	if (site.days_left <= 30) return "u-chip-warn";
	return "u-chip-ok";
}

const selectedSite = computed(() => sites.value.find((s) => s.site === picked.value?.value) || null);

/** DNS for whatever domain is actually going to be certified. */
const dns = computed(() => {
	const site = selectedSite.value;
	if (!site) return null;
	const custom = domain.value?.value;
	// A custom domain has no pre-computed check; say so rather than showing the
	// site's own result and implying it was checked.
	if (custom && custom !== site.domain) {
		return {
			level: "warn",
			detail: `${custom} has not been checked. It must have an A record pointing at this server before certbot will validate it.`,
		};
	}
	return site.dns || null;
});

const domainOptions = computed(() => {
	const site = selectedSite.value;
	if (!site) return [];
	return [
		{ label: site.domain, value: "", description: "The site's own domain." },
		...site.custom_domains.map((d) => ({
			label: d,
			value: d,
			description: "Extra domain configured for this site.",
		})),
	];
});

const preview = computed(() => {
	if (mode.value === "issue") {
		const site = picked.value?.value || "<site>";
		const extra = domain.value?.value ? ` --custom-domain ${domain.value.value}` : "";
		return `bench setup lets-encrypt ${site} -n${extra}`;
	}
	// Not `bench renew-lets-encrypt`: that command asks for confirmation and a
	// background job has no way to answer it. This is what bench's own cron runs.
	return `sudo -n certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"${
		dryRun.value ? " --dry-run" : ""
	}`;
});

const summary = computed(() => {
	if (mode.value === "issue") {
		const target = domain.value?.value || selectedSite.value?.domain || "the site";
		return `Stop nginx, ask Let's Encrypt for a certificate for ${target}, write it into the site config, rebuild nginx and start it again.`;
	}
	return dryRun.value
		? "Rehearse renewal against the staging server. Nothing is installed and no rate limit is consumed."
		: "Renew every certificate inside its renewal window. nginx starts again afterwards even if renewal fails.";
});

const canRun = computed(() => {
	if (!report.value?.ready) return false;
	if (mode.value !== "issue") return true;
	if (!picked.value?.value) return false;
	// A domain that does not resolve at all cannot validate, and the attempt
	// costs a rate-limit slot. Resolving elsewhere is allowed through — behind
	// a proxy that is normal, and only the operator knows.
	return dns.value?.level !== "danger";
});

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) return;
		error.value = "";
		readiness.fetch({ bench: props.bench });
	},
);

// Pre-select the default site, as asked — the site you meant is almost always
// the one the bench already treats as default.
watch(report, (value) => {
	if (!value || picked.value) return;
	const preferred =
		value.sites.find((s) => s.site === value.default_site) || value.sites[0] || null;
	if (preferred) picked.value = { label: preferred.site, value: preferred.site };
});

watch(picked, () => (domain.value = null));

async function run() {
	running.value = true;
	error.value = "";
	try {
		const result = await runSslResource().submit({
			bench: props.bench,
			mode: mode.value,
			site: mode.value === "issue" ? picked.value.value : null,
			domain: domain.value?.value || null,
			dry_run: mode.value === "renew" && dryRun.value ? 1 : 0,
		});
		watchJob(result.name, {
			operation: "SSL",
			app_name: mode.value === "issue" ? `SSL · ${picked.value.value}` : "SSL · Renew",
			bench: props.bench,
			status: "Queued",
		});
		toast.success(mode.value === "issue" ? "Issuing certificate" : "Renewing certificates");
		open.value = false;
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the SSL job";
	} finally {
		running.value = false;
	}
}
</script>
