<template>
	<div ref="root" class="relative">
		<button
			type="button"
			class="flex w-full items-center gap-2 rounded-md border bg-[var(--paper)] px-2.5 py-[7px] text-left text-[13px] transition-colors duration-150"
			:class="[
				open ? 'border-[var(--ink)]' : 'border-[var(--rule)] hover:border-[var(--rule-strong)]',
				disabled ? 'cursor-not-allowed opacity-50' : '',
			]"
			:disabled="disabled"
			role="combobox"
			:aria-expanded="open"
			aria-haspopup="listbox"
			@click="toggle"
			@keydown.down.prevent="openList"
		>
			<span class="min-w-0 flex-1 truncate" :class="selected ? '' : 'text-[var(--ink-ghost)]'">
				<span :class="mono && selected ? 'u-mono' : ''">{{ selected?.label || placeholder }}</span>
			</span>
			<Spinner v-if="loading" class="h-3.5 w-3.5 shrink-0 text-[var(--ink-faint)]" />
			<Icon
				v-else
				name="chevron"
				:size="13"
				class="shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
				:class="open ? '-rotate-90' : 'rotate-90'"
			/>
		</button>

		<!--
			The list opens INLINE, in normal flow, and the dialog grows to fit it.

			It is deliberately not a floating popover. Three variants were tried and
			each broke on something structural:

			  absolute  — clipped at the dialog's bottom edge (`overflow-hidden`),
			              which is the bug this component was written to fix;
			  teleported to <body> — frappe-ui's Dialog is a Headless UI modal, so a
			              click on a panel outside it counts as an outside click and
			              dismissed the ENTIRE dialog the moment you touched the
			              search box;
			  teleported into the dialog — it carries Tailwind's `transform` class,
			              which makes it the containing block for `position: fixed`,
			              so a fixed panel is clipped by `overflow-hidden` again.

			Growing the dialog sidesteps all three: every click stays inside the
			modal, nothing can clip it, and there is no position to measure or keep
			in sync on scroll. `scrollIntoView` covers the one cost — if the dialog
			grew past the viewport, the list is brought into view.
		-->
		<Transition
			enter-active-class="transition-all duration-150 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-1"
			leave-active-class="transition-all duration-100"
			leave-to-class="opacity-0"
		>
			<div
				v-if="open"
				ref="panel"
				class="mt-1 overflow-hidden rounded-lg border border-[var(--rule-strong)] bg-[var(--paper-raised)] shadow-[0_10px_30px_-12px_rgba(0,0,0,0.25)]"
			>
				<!-- Escape and Enter are stopped here, not just prevented. Without
				     .stop they bubble to the surrounding Dialog, so pressing Escape
				     to dismiss the option list closed the entire dialog and lost
				     everything already filled in. -->
				<div class="border-b border-[var(--rule)] p-1.5">
					<div class="relative">
						<Icon
							name="search"
							:size="13"
							class="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-[var(--ink-ghost)]"
						/>
						<input
							ref="search"
							v-model="query"
							type="text"
							:placeholder="searchPlaceholder"
							class="w-full rounded border border-transparent bg-[var(--paper-sunk)] py-1.5 pl-7 pr-2 text-[13px] outline-none transition-colors focus:border-[var(--rule-strong)]"
							@keydown.down.prevent="move(1)"
							@keydown.up.prevent="move(-1)"
							@keydown.enter.prevent.stop="choose(filtered[active])"
							@keydown.esc.prevent.stop="close"
						/>
					</div>
				</div>

				<ul ref="list" class="u-scroll max-h-[240px] overflow-y-auto py-1" role="listbox">
					<li
						v-for="(option, index) in filtered"
						:key="option.value"
						role="option"
						:aria-selected="option.value === modelValue?.value"
						class="cursor-pointer px-2.5 py-1.5 transition-colors duration-75"
						:class="index === active ? 'bg-[var(--paper-sunk)]' : ''"
						@mouseenter="active = index"
						@click="choose(option)"
					>
						<div class="flex items-baseline gap-2">
							<span class="u-item-label min-w-0 flex-1 truncate" :class="mono ? 'u-mono' : ''">
								{{ option.label }}
							</span>
							<span v-if="option.chip" class="u-chip shrink-0" :class="option.chipClass">
								{{ option.chip }}
							</span>
							<Icon
								v-else-if="option.value === modelValue?.value"
								name="check"
								:size="13"
								class="shrink-0 text-[var(--ink)]"
							/>
						</div>
						<p v-if="option.description" class="u-item-detail mt-0.5 line-clamp-2">
							{{ option.description }}
						</p>
					</li>

					<li v-if="!filtered.length" class="px-2.5 py-4 text-center">
						<p class="u-item-detail">{{ emptyText }}</p>
					</li>
				</ul>

				<p
					v-if="filtered.length && filtered.length < options.length"
					class="border-t border-[var(--rule)] px-2.5 py-1.5"
				>
					<span class="u-item-detail">{{ filtered.length }} of {{ options.length }}</span>
				</p>
			</div>
		</Transition>
	</div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { Spinner } from "frappe-ui";
import Icon from "./Icon.vue";

const props = defineProps({
	modelValue: { type: Object, default: null },
	options: { type: Array, default: () => [] },
	placeholder: { type: String, default: "Select…" },
	searchPlaceholder: { type: String, default: "Search" },
	emptyText: { type: String, default: "Nothing matches that." },
	loading: { type: Boolean, default: false },
	disabled: { type: Boolean, default: false },
	mono: { type: Boolean, default: false },
});
const emit = defineEmits(["update:modelValue"]);

const root = ref(null);
const search = ref(null);
const list = ref(null);
const panel = ref(null);
const open = ref(false);
const query = ref("");
const active = ref(0);

const selected = computed(
	() => props.options.find((o) => o.value === props.modelValue?.value) || props.modelValue,
);

/**
 * Matching runs over the label AND the description, so "cache" finds "Clear
 * website cache" and "index" finds "Rebuild search index" — searching only
 * names would hide half of what is there from anyone who does not already know
 * what it is called.
 */
const filtered = computed(() => {
	const q = query.value.trim().toLowerCase();
	if (!q) return props.options;
	const terms = q.split(/\s+/);
	return props.options.filter((o) => {
		const haystack = `${o.label} ${o.description || ""} ${o.keywords || ""}`.toLowerCase();
		return terms.every((t) => haystack.includes(t));
	});
});

function toggle() {
	open.value ? close() : openList();
}

async function openList() {
	if (props.disabled) return;
	open.value = true;
	query.value = "";
	active.value = Math.max(
		0,
		props.options.findIndex((o) => o.value === props.modelValue?.value),
	);
	await nextTick();
	search.value?.focus();
	scrollActiveIntoView();
	// The dialog just got taller. If that pushed the list below the fold, bring
	// it back — opening a picker you cannot see reads as nothing happening.
	panel.value?.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function close() {
	open.value = false;
}

function choose(option) {
	if (!option) return;
	emit("update:modelValue", option);
	close();
}

function move(delta) {
	if (!filtered.value.length) return;
	active.value = (active.value + delta + filtered.value.length) % filtered.value.length;
	scrollActiveIntoView();
}

function scrollActiveIntoView() {
	nextTick(() => {
		list.value?.children?.[active.value]?.scrollIntoView({ block: "nearest" });
	});
}

watch(query, () => (active.value = 0));

function onClickOutside(event) {
	if (open.value && !root.value?.contains(event.target)) close();
}

onMounted(() => document.addEventListener("mousedown", onClickOutside));
onBeforeUnmount(() => document.removeEventListener("mousedown", onClickOutside));
</script>
