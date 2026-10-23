// Sign-in through a real Keycloak with the realm in examples/keycloak (ADR 0002: every method is tested against a real
// server). Runs when KEYCLOAK_URL is set, as in CI; examples/keycloak/test.sh starts Keycloak and runs it.
import { describe, expect, it } from "vitest";
import { PRESETS } from "../src/presets.ts";
import { startProduct, type Browser } from "./helpers.ts";

const KC = process.env.KEYCLOAK_URL;
const PRODUCT_PORT = 4100;
const ADMIN = { username: process.env.KEYCLOAK_ADMIN_USERNAME ?? "admin", password: process.env.KEYCLOAK_ADMIN_PASSWORD ?? "" };

/** Keycloak's admin API, to add the people the realm leaves to each site. */
async function admin(path: string, init: { method?: string; body?: unknown } = {}) {
  const t = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", ...ADMIN }),
  });
  const { access_token } = (await t.json()) as { access_token: string };
  const res = await fetch(`${KC}/admin/realms/openasy${path}`, {
    method: init.method ?? (init.body === undefined ? "GET" : "POST"),
    headers: { authorization: `Bearer ${access_token}`, "content-type": "application/json" },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return res.status === 201 || res.status === 204 ? undefined : res.json();
}

async function addPerson(username: string, group?: string) {
  await admin("/users", {
    body: {
      username,
      email: `${username}@example.com`,
      emailVerified: true,
      enabled: true,
      firstName: username,
      lastName: "Test",
      credentials: [{ type: "password", value: "correct horse battery", temporary: false }],
    },
  });
  const [user] = (await admin(`/users?username=${username}&exact=true`)) as Array<{ id: string }>;
  if (group) {
    const [g] = (await admin(`/groups?search=${group}&exact=true`)) as Array<{ id: string }>;
    await admin(`/users/${user!.id}/groups/${g!.id}`, { method: "PUT", body: {} });
  }
}

/** Like a browser: the product sends it to Keycloak, it fills in Keycloak's sign-in form, and Keycloak sends it back. */
async function signInThroughKeycloak(b: Browser, username: string) {
  const start = await b.fetch("/api/v1/auth/oidc/keycloak/start");
  const jar = new Map<string, string>();
  const kc = async (url: string, init: RequestInit = {}) => {
    const res = await fetch(url, { ...init, redirect: "manual", headers: { ...init.headers, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      jar.set(pair!.slice(0, pair!.indexOf("=")), pair!.slice(pair!.indexOf("=") + 1));
    }
    return res;
  };
  const page = await (await kc(start.headers.get("location")!)).text();
  const action = page.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/)?.[1]?.replaceAll("&amp;", "&");
  if (!action) throw new Error("Keycloak did not show its sign-in form");
  const back = await kc(action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username, password: "correct horse battery", credentialId: "" }),
  });
  const callback = new URL(back.headers.get("location")!);
  const done = await b.fetch(callback.pathname + callback.search);
  return decodeURIComponent(done.headers.get("location") ?? "");
}

describe.skipIf(!KC)("sign-in through Keycloak", () => {
  it("maps Keycloak groups to roles, and refuses people in none of them", async () => {
    const keycloak = PRESETS.find((p) => p.id === "keycloak")!;
    const app = await startProduct(
      {
        allowInsecureIssuers: true,
        oidc: [
          {
            id: "keycloak",
            name: keycloak.name,
            issuer: `${KC}/realms/openasy`,
            clientId: "openasy-vpn",
            clientSecret: process.env.OPENASY_VPN_SECRET,
            scopes: keycloak.scopes,
            groupsClaim: keycloak.groupsClaim,
            roleMapping: { "openasy-admins": "admin", "openasy-viewers": "viewer" },
            allowInsecure: true,
          },
        ],
      },
      PRODUCT_PORT,
    );
    try {
      // New names each run, so a Keycloak kept from an earlier run works too.
      const run = Date.now().toString(36);
      await addPerson(`ada-${run}`, "openasy-admins");
      await addPerson(`noel-${run}`);
      const ada = app.browser();
      expect(await signInThroughKeycloak(ada, `ada-${run}`)).toBe("/");
      expect((await ada.json<{ user: { email: string; role: string; providers: string[] } }>("/api/v1/auth/me")).body.user).toMatchObject({
        email: `ada-${run}@example.com`,
        role: "admin",
        providers: ["keycloak"],
      });
      // Noel is in no mapped group and nobody invited him: he is refused, and no member is made for him.
      expect(await signInThroughKeycloak(app.browser(), `noel-${run}`)).toMatch(/auth_error=You have no access/);
      expect(app.db.prepare("SELECT COUNT(*) AS n FROM auth_users WHERE email = ?").get(`noel-${run}@example.com`)).toEqual({ n: 0 });
    } finally {
      await app.close();
    }
  });
});
