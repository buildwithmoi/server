/**
 * Keeping a dialog open while it is doing something you cannot get back.
 *
 * Uploading a backup, scanning a dump for the apps it needs, queueing a
 * restore — all of it lives in the dialog component, so dismissing the dialog
 * aborts the work. And there is nothing to return to: unlike a queued bench
 * command, which the job dock follows wherever you navigate, a half-finished
 * upload leaves no record. Clicking the backdrop by accident during a
 * nine-minute upload silently threw the whole thing away.
 *
 * frappe-ui's `disableOutsideClickToClose` covers the backdrop but NOT the
 * Escape key, which is wired straight to close(). This adds the missing half,
 * on the capture phase so it runs before the dialog's own handler.
 */

import { onUnmounted, watch, type Ref } from "vue";

export function useBusyGuard(busy: Ref<boolean>) {
	function onKeydown(event: KeyboardEvent) {
		if (event.key === "Escape" && busy.value) {
			event.preventDefault();
			event.stopPropagation();
		}
	}

	watch(
		busy,
		(isBusy) => {
			if (isBusy) document.addEventListener("keydown", onKeydown, true);
			else document.removeEventListener("keydown", onKeydown, true);
		},
		{ immediate: true },
	);

	// A listener left behind on a destroyed component keeps swallowing Escape
	// for every dialog opened afterwards.
	onUnmounted(() => document.removeEventListener("keydown", onKeydown, true));
}
