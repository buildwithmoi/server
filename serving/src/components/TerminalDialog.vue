<template>
	<Dialog
		v-model="open"
		:options="{ title: `Terminal · ${bench}`, size: '4xl' }"
		:disable-outside-click-to-close="running"
	>
		<template #body-content>
			<div class="flex flex-col gap-3">
				<p class="text-[12px] leading-relaxed text-[var(--ink-faint)]">
					<span class="u-mono">bash -lc</span> in
					<span class="u-mono">{{ benchPath || bench }}</span>, as the bench user.
					Input is closed, so anything interactive
					(<span class="u-mono">vim</span>, <span class="u-mono">top</span>,
					<span class="u-mono">mariadb</span>) exits straight away.
					Every command is recorded as a security finding.
				</p>

				<!--
					A terminal is dark in both themes on purpose. It is not the
					app's surface, it is a window onto somebody else's — and
					every terminal anyone has used looks like this, which is
					most of what "a terminal feel" means.
				-->
				<div
					ref="scrollback"
					class="u-term u-scroll h-[min(46vh,28rem)] min-h-[9rem] overflow-y-auto rounded-lg p-3 text-[12.5px] leading-[1.55]"
					@click="focusPrompt"
				>
					<p v-if="!history.length" class="u-term-dim">
						{{ bench }} — type a command and press Enter.
					</p>

					<div v-for="(entry, index) in history" :key="index" class="mb-2 last:mb-0">
						<p class="whitespace-pre-wrap break-all">
							<span class="u-term-prompt">$</span> {{ entry.command }}
						</p>
						<p v-if="entry.output" class="whitespace-pre-wrap break-all u-term-out">{{ entry.output }}</p>
						<p v-if="entry.status === 'Running'" class="u-term-dim flex items-center gap-2">
							<Spinner class="h-3 w-3" /> running…
						</p>
						<p v-else-if="entry.exitCode" class="u-term-bad">
							exited {{ entry.exitCode }}
						</p>
					</div>
				</div>

				<!-- The prompt line. Deliberately looks like the scrollback
				     above it rather than like a form field. -->
				<div class="u-term u-term-input flex items-start gap-2 rounded-lg px-3 py-2.5">
					<span class="u-term-prompt mt-[1px] shrink-0 text-[12.5px]">$</span>
					<textarea
						ref="prompt"
						v-model="command"
						rows="1"
						spellcheck="false"
						autocapitalize="off"
						autocomplete="off"
						:disabled="running"
						placeholder="git status --porcelain"
						class="u-scroll max-h-[7rem] min-h-[1.4rem] flex-1 resize-none bg-transparent text-[12.5px] leading-[1.55] outline-none disabled:opacity-50"
						@keydown.enter.exact.prevent="run"
						@keydown="onKey"
					/>
					<Button v-if="running" variant="subtle" @click="stop">Stop</Button>
				</div>

				<div class="flex items-center justify-between gap-3">
					<p class="text-[11.5px] text-[var(--ink-faint)]">
						Enter runs · Shift+Enter adds a line · ↑ recalls
					</p>
					<label v-if="!confirmed" class="flex items-center gap-2 text-[11.5px]">
						<span class="text-[var(--ink-faint)]">
							Type <span class="u-mono">{{ bench }}</span> to unlock
						</span>
						<input
							v-model.trim="confirm"
							type="text"
							autocomplete="off"
							:placeholder="bench"
							class="w-40 rounded-md border border-[var(--danger-border)] bg-[var(--paper)] px-2 py-1 text-[12px] outline-none focus:border-[var(--ink)]"
						/>
					</label>
					<button
						v-else-if="history.length"
						class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
						@click="history = []"
					>
						Clear
					</button>
				</div>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex justify-end">
				<Button :disabled="running" @click="open = false">Close</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, nextTick, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import { cancelJob, watchJob } from "../jobs";
import { installRequestResource, runConsoleResource } from "../api";

const POLL_MS = 900;

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	benchPath: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started"]);

const runResource = runConsoleResource();
const pollResource = installRequestResource();

const command = ref("");
const confirm = ref("");
const history = ref([]);
const running = ref(false);
const error = ref("");
const scrollback = ref(null);
const prompt = ref(null);

/** Where ↑ currently is in the command history. -1 means "not recalling". */
const recallIndex = ref(-1);
let timer = null;
let liveJob = "";

const open = computed({
	get: () => props.modelValue,
	set: (value) => emit("update:modelValue", value),
});

// Unlocked once per session rather than per command. A terminal you must
// re-confirm for every line is one nobody uses; confirming that you meant to
// open a shell at all is the part that matters.
const confirmed = computed(() => confirm.value === props.bench);

function focusPrompt() {
	if (!running.value) prompt.value?.focus();
}

async function toBottom() {
	await nextTick();
	if (scrollback.value) scrollback.value.scrollTop = scrollback.value.scrollHeight;
}

function onKey(event) {
	// Bound as one handler rather than three modifiers so the arrow keys are
	// matched on `event.key` directly — and so a future addition (Ctrl+C, say)
	// has one place to live.
	if (event.key === "ArrowUp") recall(-1, event);
	else if (event.key === "ArrowDown") recall(1, event);
}

function recall(direction, event) {
	const past = history.value.map((h) => h.command);
	if (!past.length) return;
	event.preventDefault();

	if (recallIndex.value === -1) recallIndex.value = past.length;
	recallIndex.value = Math.min(past.length, Math.max(0, recallIndex.value + direction));
	command.value = recallIndex.value === past.length ? "" : past[recallIndex.value];
}

async function run() {
	const text = command.value.trim();
	if (!text || running.value) return;
	if (!confirmed.value) {
		error.value = `Type “${props.bench}” in the box below to unlock the terminal.`;
		return;
	}

	error.value = "";
	running.value = true;
	recallIndex.value = -1;
	const entry = { command: text, output: "", status: "Running", exitCode: 0 };
	history.value.push(entry);
	command.value = "";
	await toBottom();

	try {
		const result = await runResource.submit({
			bench: props.bench,
			command: text,
			confirm: props.bench,
		});
		liveJob = result.name;
		entry.name = result.name;
		emit("started", result.name);
		poll(entry);
	} catch (caught) {
		entry.status = "Failed";
		entry.output = caught.messages?.[0] || "The command could not be started.";
		running.value = false;
		liveJob = "";
		await toBottom();
	}
}

function poll(entry) {
	clearTimeout(timer);
	timer = setTimeout(async () => {
		try {
			const data = await pollResource.submit({ name: entry.name });
			// The pre-flight notes and the echoed `$ command` are already on
			// screen — the prompt line above is the echo. Trimming them keeps
			// the scrollback reading like a terminal instead of a job log.
			entry.output = stripPreamble(data.output || "", entry.command);
			entry.status = data.status;
			entry.exitCode = data.exit_code;
			await toBottom();

			if (!data.is_terminal) {
				poll(entry);
				return;
			}
			running.value = false;
			liveJob = "";
			focusPrompt();
		} catch {
			// A transient failure should not kill the session; the next tick
			// usually succeeds, and a genuinely dead job ends up terminal.
			poll(entry);
		}
	}, POLL_MS);
}

/** Lines the job machinery adds around the command's own output. */
const TRAILERS = ["Bench re-read from disk.", "Could not re-read the bench:"];

/**
 * The job log opens with the pre-flight notes and its own `$ <command>` echo,
 * and closes with the rescan step's note. All of it is useful in the Installs
 * view and all of it is noise here, where the command is the line directly
 * above and the reader is expecting a shell.
 */
function stripPreamble(output, text) {
	const lines = output.split("\n");
	const echo = lines.findIndex((line) => line.trim() === `$ ${text}`);
	const body = echo === -1 ? lines : lines.slice(echo + 1);

	// Blank lines have to be dropped as part of the same loop, not before it:
	// the rescan note is followed by one, so a pop that only matched trailers
	// stopped on the blank and left the note on screen.
	while (body.length) {
		const last = body[body.length - 1].trim();
		if (last === "" || TRAILERS.some((t) => last.startsWith(t))) {
			body.pop();
			continue;
		}
		break;
	}
	return body.join("\n").replace(/\s+$/, "");
}

async function stop() {
	if (!liveJob) return;
	try {
		await cancelJob(liveJob);
		toast.success("Stopping…");
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not stop it.";
	}
}

watch(
	() => props.modelValue,
	(isOpen) => {
		if (isOpen) {
			nextTick(focusPrompt);
			return;
		}
		clearTimeout(timer);
		// Closing while something is running hands it to the dock rather than
		// losing it — the same contract every other dialog here has.
		if (running.value && liveJob) {
			watchJob(liveJob, {
				operation: "Console",
				app_name: `Console · ${history.value.at(-1)?.command || ""}`,
				bench: props.bench,
				status: "Running",
			});
		}
		running.value = false;
		liveJob = "";
		command.value = "";
		confirm.value = "";
		error.value = "";
		history.value = [];
	},
);
</script>
