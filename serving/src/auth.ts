/**
 * Session handling, with no dependency outside this repository.
 *
 * WHY THIS IS NOT IMPORTED FROM doppio. The scaffold this SPA came from reaches
 * out with `../../../doppio/libs/controllers/auth`, which escapes the repo into
 * a SIBLING APP. That makes doppio a build-time requirement of `server`: clone
 * this app onto a fresh server without it and the frontend does not compile —
 * a failure that appears at build time, in a path nobody reads, for a
 * dependency that is not declared anywhere.
 *
 * What was actually being used amounted to reading a cookie and calling two
 * endpoints, so it is written out here instead. The app is now self-contained,
 * and `bench get-app` on a bare bench works.
 */

import { reactive } from "vue";
import { frappeRequest } from "frappe-ui";

function readCookies(): Record<string, string> {
	return Object.fromEntries(
		document.cookie
			.split("; ")
			.filter(Boolean)
			.map((part) => {
				const index = part.indexOf("=");
				return index === -1
					? [part, ""]
					: [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
			}),
	);
}

export interface Session {
	isLoggedIn: boolean;
	user: string | null;
	login(email: string, password: string): Promise<unknown>;
	logout(): Promise<void>;
}

/**
 * Frappe sets `user_id` on login and resets it to "Guest" on logout, so the
 * cookie is the authoritative answer to "am I signed in" without a round trip
 * on every page load.
 */
export function createSession(): Session {
	const cookies = readCookies();
	const user = cookies.user_id && cookies.user_id !== "Guest" ? cookies.user_id : null;

	return reactive<Session>({
		isLoggedIn: Boolean(user),
		user,

		async login(email: string, password: string) {
			const result = await frappeRequest({
				url: "/api/method/login",
				method: "POST",
				params: { usr: email, pwd: password },
			});
			const signedIn = readCookies();
			this.isLoggedIn = true;
			this.user = signedIn.user_id || email;
			return result;
		},

		async logout() {
			try {
				await frappeRequest({ url: "/api/method/logout", method: "POST" });
			} finally {
				this.isLoggedIn = false;
				this.user = null;
				// A full reload rather than a router push: it clears every
				// cached resource and in-flight poller in one step, which is
				// what signing out should mean.
				window.location.href = "/serving/login";
			}
		},
	});
}
