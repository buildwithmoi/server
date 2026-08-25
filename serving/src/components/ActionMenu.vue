<template>
	<div ref="root" class="relative">
		<button
			type="button"
			class="flex items-center gap-1.5 rounded-md border px-2.5 py-[6px] text-[13px] transition-colors duration-150"
			:class="open
				? 'border-[var(--ink)] bg-[var(--paper-sunk)]'
				: 'border-[var(--rule)] hover:bg-[var(--paper-sunk)]'"
			aria-haspopup="menu"
			:aria-expanded="open"
			@click="open = !open"
		>
			<Icon v-if="icon" :name="icon" :size="14" />
			{{ label }}
			<Icon
				name="chevron"
				:size="12"
				class="text-[var(--ink-ghost)] transition-transform duration-200"
				:class="open ? '-rotate-90' : 'rotate-90'"
			/>
		</button>

		<Transition
			enter-active-class="transition-all duration-150 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-1"
			leave-active-class="transition-all duration-100"
			leave-to-class="opacity-0"
		>
			<!--
				Owned rather than themed. frappe-ui's Dropdown renders the label and
				its description at almost the same weight, so nothing tells the eye
				which is the action and which is the explanation. Here the label is
				near-black and carries the weight; the detail is smaller and faint.
			-->
			<div
				v-if="open"
				role="menu"
				class="u-scroll absolute right-0 z-50 mt-1 max-h-[min(70vh,32rem)] w-[290px] overflow-y-auto overscroll-contain rounded-lg border border-[var(--rule-strong)] bg-[var(--paper-raised)] py-1 shadow-[0_10px_30px_-12px_rgba(0,0,0,0.3)]"
			>
				<template v-for="(item, index) in visible" :key="item.label">
					<div
						v-if="item.separator"
						class="my-1 border-t border-[var(--rule)]"
						:class="index === 0 ? 'hidden' : ''"
					/>
					<button
						v-else
						type="button"
						role="menuitem"
						class="flex w-full items-start gap-2.5 px-3 py-2 text-left transition-colors duration-75 hover:bg-[var(--paper-sunk)]"
						@click="run(item)"
					>
						<Icon
							v-if="item.icon"
							:name="item.icon"
							:size="15"
							class="mt-[2px] shrink-0"
							:class="item.danger ? 'u-danger' : 'text-[var(--ink-soft)]'"
						/>
						<span class="min-w-0 flex-1">
							<span class="u-item-label block" :class="item.danger ? 'u-danger' : ''">
								{{ item.label }}
							</span>
							<span v-if="item.description" class="u-item-detail mt-0.5 block">
								{{ item.description }}
							</span>
						</span>
					</button>
				</template>
			</div>
		</Transition>
	</div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({
	label: { type: String, default: "Actions" },
	icon: { type: String, default: "" },
	// Each: { label, description?, icon?, danger?, separator?, onClick, condition? }
	options: { type: Array, default: () => [] },
});

const root = ref(null);
const open = ref(false);

// `condition` hides an item rather than disabling it: a greyed-out row invites a
// click and then explains nothing.
const visible = computed(() => props.options.filter((o) => !o.condition || o.condition()));

function run(item) {
	open.value = false;
	item.onClick?.();
}

function onClickOutside(event) {
	if (open.value && root.value && !root.value.contains(event.target)) open.value = false;
}

onMounted(() => document.addEventListener("mousedown", onClickOutside));
onBeforeUnmount(() => document.removeEventListener("mousedown", onClickOutside));
</script>
