<template>
	<Dialog
		v-model="open"
		:options="{ title: `Run a command · ${bench}`, size: 'xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<!--
					Said before the box, not after a stuck job. stdin is closed
					for every job in this app, so an interactive program exits in
					the first second — an operator who types `top` and sees it
					die needs to have been told why beforehand.
				-->
				<div class="u-note flex items-start gap-2.5">
					<Icon name="terminal" :size="15" class="mt-0.5 shrink-0 text-[var(--ink-faint)]" />
					<p class="text-[12.5px] leading-relaxed">
						Runs as the bench user in
						<span class="u-mono">{{ benchPath || bench }}</span>, through
						<span class="u-mono">bash -lc</span> — so pipes,
						<span class="u-mono">&amp;&amp;</span> and redirection work.
						Input is closed, so anything interactive
						(<span class="u-mono">vim</span>, <span class="u-mono">top</span>,
						<span class="u-mono">mariadb</span>,
						<span class="u-mono">bench console</span>) will exit straight away.
					</p>
				</div>

				<label class="flex flex-col gap-1.5">
					<span class="u-label">Command</span>
					<textarea
						v-model="command"
						rows="3"
						spellcheck="false"
						autocapitalize="off"
						autocomplete="off"
						placeholder="git status --porcelain"
						class="u-mono u-scroll resize-y rounded-md border border-[var(--rule)] bg-[var(--paper)]
						       px-2.5 py-2 text-[13px] leading-relaxed outline-none transition-colors
						       focus:border-[var(--ink)]"
						@keydown.enter.exact.prevent="canRun && run()"
					/>
					<p class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						Enter runs it; Shift+Enter adds a line.
						{{ command.length }}/{{ MAX }} characters.
					</p>
				</label>

				<!--
					Every use is recorded. Saying so here is not a warning about
					danger, it is telling the operator what the tool does with
					what they type — which they are entitled to know before they
					type it.
				-->
				<div class="u-note u-note-warn flex items-start gap-2.5">
					<Icon name="shield" :size="15" class="u-warn mt-0.5 shrink-0" />
					<p class="text-[12.5px] leading-relaxed">
						This is the one thing here that is not a checked, fixed command, so every use
						is recorded as a security finding — copied off this server as it is written
						and listed in the daily digest, with the full output kept against the job.
					</p>
				</div>

				<div class="u-note u-note-danger flex flex-col gap-1.5">
					<!--
						`normal-case` on the name specifically: `u-label`
						uppercases its content, which rendered the confirmation
						target as FB-15-1 while the bench is actually fb-15-1.
						Asking somebody to type a string and then showing them a
						different string is a good way to have them type it.
					-->
					<span class="u-label">
						Type <span class="u-mono normal-case">{{ bench }}</span> to confirm
					</span>
					<input
						v-model.trim="confirm"
						type="text"
						autocomplete="off"
						:placeholder="bench"
						class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
					/>
				</div>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex items-center justify-end gap-2">
				<div v-if="busy" class="mr-auto flex items-center gap-2 text-[12.5px] text-[var(--ink-faint)]">
					<Spinner class="h-3.5 w-3.5" />
					<span>Starting…</span>
				</div>
				<Button :disabled="busy" @click="open = false">Cancel</Button>
				<Button variant="solid" :loading="running" :disabled="!canRun" @click="run">Run</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import { watchJob } from "../jobs";
import { useBusyGuard } from "../busy";
import { runConsoleResource } from "../api";

/** Mirrors console.MAX_COMMAND on the Python side. */
const MAX = 4000;

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	benchPath: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started"]);

const resource = runConsoleResource();
const command = ref("");
const confirm = ref("");
const running = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (value) => emit("update:modelValue", value),
});

// Only the moment between pressing Run and the job existing. Once the row is
// created the dock owns it, so closing the dialog is harmless.
const busy = computed(() => running.value);
useBusyGuard(busy);

const canRun = computed(
	() => !running.value && command.value.trim().length > 0 && command.value.length <= MAX && confirm.value === props.bench,
);

async function run() {
	if (!canRun.value) return;
	running.value = true;
	error.value = "";
	try {
		const result = await resource.submit({
			bench: props.bench,
			command: command.value,
			confirm: confirm.value,
		});
		watchJob(result.name, {
			operation: "Console",
			app_name: result.app_name || "Console",
			bench: props.bench,
			status: "Queued",
		});
		toast.success("Running — the output appears in the dock.");
		open.value = false;
		emit("started", result.name);
	} catch (caught) {
		error.value = caught.messages?.[0] || "The command could not be started.";
	} finally {
		running.value = false;
	}
}

// Cleared on close rather than on open: a half-typed command should not
// survive to be run against whichever bench the dialog opens on next.
watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) {
			command.value = "";
			confirm.value = "";
			error.value = "";
		}
	},
);
</script>
