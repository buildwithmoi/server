import { createApp, reactive } from "vue";
import { setConfig, frappeRequest } from "frappe-ui";

import "./style.css";
import App from "./App.vue";
import router from "./router";
import resourceManager from "../../../doppio/libs/resourceManager";
import call from "../../../doppio/libs/controllers/call";
import Auth from "../../../doppio/libs/controllers/auth";

// frappe-ui's data layer speaks to /api/method for us and gives every request a
// loading/error state, which is what the skeletons and toasts are driven from.
setConfig("resourceFetcher", frappeRequest);

const app = createApp(App);
const auth = reactive(new Auth());

app.use(router);
app.use(resourceManager);

app.provide("$auth", auth);
app.provide("$call", call);

// NOTE: doppio's socket controller is deliberately NOT wired up. It hardcodes
// port 9000 while this bench runs socketio on 9008, so importing it just opens
// a connection that can never succeed and logs errors forever. Realtime is not
// needed yet; when it is, the port has to be reconciled first (and the fix
// belongs in doppio, which is a different repository).

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
