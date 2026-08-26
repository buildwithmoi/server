/**
 * Reporting a failure that happened in the browser.
 *
 * Everything else this app logs happens on the server. A Vue component that
 * throws leaves nothing anywhere — the page goes blank or a panel stays empty,
 * and the only record is a console the operator has already closed and a
 * screenshot they have to remember to take.
 *
 * These go into the same Error Log the server writes to, so they appear on the
 * Crashes page beside the server-side ones rather than in a second place to
 * remember to look.
 *
 * THREE THINGS KEEP IT FROM BECOMING THE PROBLEM IT REPORTS.
 *
 *   A component throwing inside a render loop fires this hundreds of times a
 *   second, so identical messages are sent once and then counted, not resent.
 *
 *   A failure to report must never itself report — that is an unbounded loop
 *   between the page and the server — so the send is deliberately silent and
 *   its own errors are swallowed.
 *
 *   The endpoint is rate limited server-side as well, because a client-side
 *   guard is only as good as the client honouring it.
 */

const REPORTED = new Set<string>();
const LIMIT = 20;

let sent = 0;

async function report(kind: string, message: string, stack: string) {
	if (sent >= LIMIT) return;

	// Same message from the same place is the same fault, however many times a
	// re-render produces it.
	const key = `${kind}:${message}:${stack.slice(0, 200)}`;
	if (REPORTED.has(key)) return;
	REPORTED.add(key);
	sent += 1;

	try {
		await fetch("/api/method/server.api.report_client_error", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Frappe-CSRF-Token": (window as any).csrf_token,
			},
			body: JSON.stringify({
				kind,
				message: String(message).slice(0, 500),
				stack: String(stack).slice(0, 8000),
				route: window.location.pathname + window.location.search,
			}),
		});
	} catch {
		// Silent on purpose. Reporting a failure to report is a loop, and the
		// operator is already looking at whatever went wrong.
	}
}

/** Attach to everything that can throw without anybody catching it. */
export function captureBrowserErrors(app: { config: { errorHandler?: unknown } }) {
	window.addEventListener("error", (event) => {
		report("error", event.message || "Unknown error", event.error?.stack || `${event.filename}:${event.lineno}`);
	});

	// A rejected promise nobody awaited — the shape almost every failed API
	// call takes, and the one `window.onerror` does not see.
	window.addEventListener("unhandledrejection", (event) => {
		const reason: any = event.reason;
		report(
			"unhandled rejection",
			reason?.messages?.[0] || reason?.message || String(reason),
			reason?.stack || "",
		);
	});

	// Vue swallows render errors into its own handler rather than letting them
	// reach window.onerror, so without this the most likely failure in a Vue
	// app is the one that goes unrecorded.
	app.config.errorHandler = (error: any, _instance: unknown, info: string) => {
		report(`vue ${info}`, error?.message || String(error), error?.stack || "");
		// Still logged locally: someone with the console open should not lose
		// the error just because it was also reported.
		console.error(error);
	};
}
