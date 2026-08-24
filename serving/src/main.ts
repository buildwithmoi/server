import { createApp } from "vue";
import { setConfig, frappeRequest } from "frappe-ui";

import "./style.css";
import App from "./App.vue";
import router from "./router";
import { createSession } from "./auth";

// frappe-ui's data layer speaks to /api/method for us and gives every request a
// loading/error state, which is what the skeletons and toasts are driven from.
setConfig("resourceFetcher", frappeRequest);

const app = createApp(App);
const auth = createSession();

app.use(router);
app.provide("$auth", auth);

// NOTE: there is no socket connection. Job progress is polled instead — see
// the reasoning in src/jobs.ts. Nothing in this app imports from a sibling app,
// so `bench get-app server` builds on a bench that has nothing else installed.

router.beforeEach(async (to, _from, next) => {
	if (to.matched.some((record) => !record.meta.isLoginPage)) {
		if (!auth.isLoggedIn) {
			next({ name: "Login", query: { route: to.path } });
		} else {
			next();
		}
	} else {
		if (auth.isLoggedIn) {
			next({ name: "Dashboard" });
		} else {
			next();
		}
	}
});

app.mount("#app");
