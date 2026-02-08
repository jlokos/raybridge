import { loadRaycastAuthData } from "./auth.js";

const auth = await loadRaycastAuthData();

console.log(`oauth_extensions=${auth.tokens.size}`);
console.log(`prefs_extensions=${Object.keys(auth.prefs).length}`);

