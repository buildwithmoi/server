<template>
	<Teleport to="body">
		<Transition
			enter-active-class="transition-all duration-300 ease-[var(--ease)]"
			enter-from-class="opacity-0 translate-y-4"
			leave-active-class="transition-all duration-200 ease-[var(--ease)]"
			leave-to-class="opacity-0 translate-y-4"
		>
			<div
				v-if="allJobs.length"
				class="fixed bottom-4 right-4 z-50 flex w-[min(calc(100vw-2rem),460px)] flex-col gap-2"
			>
				<article
					v-for="job in allJobs"
					:key="job.name"
					class="overflow-hidden rounded-xl border border-[var(--rule-strong)] bg-[var(--paper-raised)] shadow-[0_8px_28px_-12px_rgba(0,0,0,0.35)]"
				>
					<!-- collapsed bar: always visible, always clickable -->
					<button
						class="flex w-full items-center gap-3 px-3.5 py-2.5 text-left transition-colors duration-150 hover:bg-[var(--paper-sunk)]"
						:aria-expanded="expandedJob?.name === job.name"
						@click="toggle(job)"
					>
						<!-- Motion is the signal that it is alive. A static label
						     cannot distinguish "running" from "stuck". -->
						<span v-if="!job.is_terminal" class="flex h-4 w-4 shrink-0 items-end gap-[2px]" aria-hidden="true">
							<i v-for="n in 3" :key="n" class="job-bar" :style="{ animationDelay: `${(n - 1) * 140}ms` }" />
						</span>
						<OutcomeMark
							v-else
							:outcome="okStatuses.includes(job.status) ? 'Success' : 'Failure'"
							:with-label="false"
							class="shrink-0"
						/>

						<span class="min-w-0 flex-1">
							<span class="block truncate text-[13px] font-medium">
								{{ job.is_terminal ? terminalVerb(job) : activeVerb(job) }}
								<span class="u-mono">{{ job.app_name || job.name }}</span>
							</span>
							<span class="block truncate text-[11.5px] text-[var(--ink-faint)]">
								{{ job.bench }}<span v-if="job.branch"> · {{ job.branch }}</span> ·
								{{ job.is_terminal ? job.status.toLowerCase() : tick(job) }}
							</span>
						</span>

						<Icon
							name="chevron"
							:size="14"
							class="shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
							:class="expandedJob?.name === job.name ? '-rotate-90' : 'rotate-90'"
						/>
					</button>

					<!-- expanded: the actual terminal output -->
					<Transition
						enter-active-class="transition-all duration-250 ease-[var(--ease)]"
						enter-from-class="opacity-0 max-h-0"
						enter-to-class="opacity-100 max-h-[420px]"
						leave-active-class="transition-all duration-200 ease-[var(--ease)]"
						leave-from-class="opacity-100 max-h-[420px]"
						leave-to-class="opacity-0 max-h-0"
					>
						<div v-if="expandedJob?.name === job.name" class="overflow-hidden border-t border-[var(--rule)]">
							<p v-if="job.command" class="u-mono truncate bg-[var(--paper-sunk)] px-3.5 py-1.5 text-[11px] text-[var(--ink-soft)]">
								$ {{ job.command }}
							</p>

							<!-- Steps first. A wall of git output does not say which
							     part is slow or which part broke; the step list does,
							     and folds the output under the step it belongs to. -->
							<div v-if="job.steps?.length" class="max-h-[320px] overflow-y-auto u-scroll px-2.5 py-2.5">
								<JobSteps :steps="job.steps" />
							</div>
							<pre
								v-else
								:ref="(el) => setLogEl(job.name, el)"
								class="u-mono u-scroll max-h-[300px] overflow-auto whitespace-pre-wrap break-words px-3.5 py-2.5 text-[11.5px] leading-relaxed"
							>{{ job.output || "waiting for output…" }}</pre>
							<p v-if="job.error_summary" class="border-t border-[var(--rule)] px-3.5 py-2 text-[12px] leading-relaxed">
								{{ job.error_summary }}
							</p>
							<div class="flex items-center justify-between gap-2 border-t border-[var(--rule)] px-3.5 py-2">
								<RouterLink
									:to="{ name: 'Installs' }"
									class="text-[11.5px] text-[var(--ink-faint)] underline-offset-2 hover:text-[var(--ink)] hover:underline"
								>Open in App Installs</RouterLink>
								<button
									v-if="job.is_terminal"
									class="text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
									@click.stop="dismiss(job.name)"
								>Dismiss</button>
							</div>
						</div>
					</Transition>
				</article>
			</div>
		</Transition>
	</Teleport>
</template>

<script setup>
import { nextTick, onUnmounted, ref, watch } from "vue";
import Icon from "./Icon.vue";
import JobSteps from "./JobSteps.vue";
import OutcomeMark from "./OutcomeMark.vue";
import { allJobs, dismiss, elapsed, expand, expandedJob, formatElapsed } from "../jobs";

const logEls = ref({});
const now = ref(Date.now());

// One interval for every ticking timer on screen.
const ticker = setInterval(() => (now.value = Date.now()), 1000);
onUnmounted(() => clearInterval(ticker));

function tick(job) {
	void now.value; // re-evaluate every second
	return formatElapsed(elapsed(job));
}

const activeVerb = (job) => (job.operation === "Pull" ? "Updating" : "Cloning");
// A warning is not a failure. Showing it as one recreates exactly the
// confusion this status exists to remove.
const okStatuses = ["Success", "Completed With Warnings"];

const terminalVerb = (job) => {
	const noun =
		job.operation === "Pull" ? "Update" : job.operation === "Command" ? "Command" : "Clone";
	if (job.status === "Completed With Warnings") return noun + " done, with a warning —";
	if (okStatuses.includes(job.status)) {
		return { Update: "Updated", Command: "Ran", Clone: "Cloned" }[noun];
	}
	return noun + " failed —";
};

function toggle(job) {
	expand(expandedJob.value?.name === job.name ? null : job.name);
}

function setLogEl(name, el) {
	if (el) logEls.value[name] = el;
}

// Follow the tail as output arrives, the way a terminal does.
watch(
	() => expandedJob.value?.output,
	async () => {
		await nextTick();
		const el = logEls.value[expandedJob.value?.name];
		if (el) el.scrollTop = el.scrollHeight;
	},
);
</script>

<style scoped>
/*
 * Three bars rising and falling — a terminal that is doing something. Chosen
 * over a spinner because a spinner reads as "waiting for a response" while this
 * reads as "work is happening", which is the truer statement for a clone.
 */
.job-bar {
	display: block;
	width: 3px;
	height: 100%;
	background: var(--ink);
	border-radius: 1px;
	animation: job-bounce 900ms var(--ease) infinite;
	transform-origin: bottom;
}

@keyframes job-bounce {
	0%,
	100% {
		transform: scaleY(0.35);
		opacity: 0.55;
	}
	50% {
		transform: scaleY(1);
		opacity: 1;
	}
}

@media (prefers-reduced-motion: reduce) {
	.job-bar {
		animation: none;
		transform: scaleY(0.7);
	}
}
</style>
