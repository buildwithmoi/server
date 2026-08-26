<!--
  A monochrome table with its own loading and empty states.

  Columns are described by objects rather than markup so every list page renders
  the same way — same row height, same header treatment, same skeleton — instead
  of three tables that drift apart as they are edited.
-->
<template>
	<div class="u-card overflow-hidden">
		<!--
			Scrolls in BOTH directions. It used to grow vertically and push the
			page, so on a list of fifty the column headings were off the top of
			the screen by the tenth row and you were reading unlabelled columns.
			Capped here instead, with the header pinned.

			`maxHeight` is a cap, not a height: a short table never reaches it
			and so never grows a scrollbar it did not need.
		-->
		<div class="u-scroll overflow-auto" :style="{ maxHeight: maxHeight }">
			<table class="w-full border-collapse text-left">
				<thead class="sticky top-0 z-10">
					<tr class="border-b border-[var(--rule)] bg-[var(--paper-sunk)]">
						<th
							v-for="col in columns"
							:key="col.key"
							scope="col"
							class="u-label whitespace-nowrap border-b border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2 font-medium"
							:style="col.width ? { width: col.width } : null"
						>{{ col.label }}</th>
					</tr>
				</thead>

				<tbody v-if="loading">
					<tr v-for="n in skeletonRows" :key="`s${n}`" class="border-b border-[var(--rule)] last:border-0">
						<td v-for="col in columns" :key="col.key" class="px-3 py-2.5">
							<Skeleton height="0.85rem" :width="col.skeletonWidth || '70%'" />
						</td>
					</tr>
				</tbody>

				<tbody v-else>
					<tr
						v-for="(row, i) in rows"
						:key="row.name || i"
						class="border-b border-[var(--rule)] transition-colors duration-100 last:border-0 hover:bg-[var(--paper-sunk)]"
						:class="clickable ? 'cursor-pointer' : ''"
						:tabindex="clickable ? 0 : undefined"
						:role="clickable ? 'link' : undefined"
						@click="clickable && $emit('row-click', row)"
						@keydown.enter="clickable && $emit('row-click', row)"
					>
						<td
							v-for="col in columns"
							:key="col.key"
							class="px-3 py-2.5 align-top text-[13px]"
							:class="col.mono ? 'u-mono' : ''"
						>
							<slot :name="`cell-${col.key}`" :row="row" :value="row[col.key]">
								<span :class="col.muted ? 'text-[var(--ink-faint)]' : ''">
									{{ format(row[col.key], col) }}
								</span>
							</slot>
						</td>
					</tr>
				</tbody>
			</table>
		</div>

		<EmptyState
			v-if="!loading && !rows.length"
			:title="emptyTitle"
			:hint="emptyHint"
		>
			<!-- For an empty state that has something to explain: which
			     directory was searched, which filter is hiding everything. -->
			<slot name="empty-extra" />
		</EmptyState>

		<!-- pager -->
		<div
			v-if="!loading && total > pageLength"
			class="flex items-center justify-between gap-3 border-t border-[var(--rule)] px-3 py-2"
		>
			<p class="u-num text-[12px] text-[var(--ink-faint)]">
				{{ (start + 1).toLocaleString() }}–{{ Math.min(start + rows.length, total).toLocaleString() }}
				of {{ total.toLocaleString() }}
			</p>
			<div class="flex items-center gap-1">
				<button
					class="rounded-md px-2 py-1 text-[12px] text-[var(--ink-soft)] transition-colors hover:bg-[var(--paper-sunk)] disabled:cursor-not-allowed disabled:opacity-35"
					:disabled="start === 0"
					@click="$emit('page', Math.max(start - pageLength, 0))"
				>Previous</button>
				<button
					class="rounded-md px-2 py-1 text-[12px] text-[var(--ink-soft)] transition-colors hover:bg-[var(--paper-sunk)] disabled:cursor-not-allowed disabled:opacity-35"
					:disabled="start + pageLength >= total"
					@click="$emit('page', start + pageLength)"
				>Next</button>
			</div>
		</div>
	</div>
</template>

<script setup>
import Skeleton from "./Skeleton.vue";
import EmptyState from "./EmptyState.vue";

const props = defineProps({
	columns: { type: Array, required: true },
	rows: { type: Array, default: () => [] },
	loading: { type: Boolean, default: false },
	total: { type: Number, default: 0 },
	start: { type: Number, default: 0 },
	pageLength: { type: Number, default: 50 },
	skeletonRows: { type: Number, default: 8 },
	emptyTitle: { type: String, default: "Nothing here yet" },
	emptyHint: { type: String, default: "" },
	// Rows become keyboard-focusable as well as clickable — a table row that
	// only responds to a mouse is unreachable for anyone navigating by keyboard.
	clickable: { type: Boolean, default: false },
	//: How tall the table may get before its rows scroll instead of the page.
	//: Viewport-relative so it adapts to the window rather than assuming one,
	//: and generous enough that a handful of rows never triggers it.
	maxHeight: { type: String, default: "min(68vh, 46rem)" },
});

defineEmits(["page", "row-click"]);

function format(value, col) {
	if (value === null || value === undefined || value === "") return "—";
	if (col.type === "datetime") return formatDateTime(value);
	if (col.type === "number") return Number(value).toLocaleString();
	return value;
}

function formatDateTime(value) {
	const d = new Date(String(value).replace(" ", "T"));
	if (Number.isNaN(d.getTime())) return value;
	return d.toLocaleString(undefined, {
		day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
	});
}
</script>
