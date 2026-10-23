import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { hashPassword, matchTotp, recoveryCodes, sealer, totp, verifyPassword } from "../src/crypto.ts";
import { addTotp, codeAt, createOwner, invite, oidcSignIn, PASSWORD, SoftPasskey, startIdp, startProduct, type Browser } from "./helpers.ts";

let app: Awaited<ReturnType<typeof startProduct>>;
beforeEach(async () => {
  app = await startProduct();
});
afterEach(() => app.close());

const signIn = (b: Browser, email = "owner@example.com", password = PASSWORD) => b.json<{ status: string; methods?: string[]; mfaSetupRequired?: boolean }>("/api/v1/auth/login", { body: { email, password } });
const needs = (b: Browser, role: string) => b.json<{ code?: string; kind?: string }>(`/api/v1/needs/${role}`);

describe("crypto", () => {
  it("hashes passwords with argon2id and verifies them", async () => {
    const h = await hashPassword("secret password");
    expect(h).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await verifyPassword("secret password", h)).toBe(true);
    expect(await verifyPassword("Secret password", h)).toBe(false);
    expect(await verifyPassword("x", "not a hash")).toBe(false);
  });

  it("matches RFC 6238 test vectors", () => {
    // RFC 6238 appendix B, SHA-1, last 6 digits.
    const secret = Buffer.from("12345678901234567890");
    expect(totp(secret, Math.floor(59 / 30))).toBe("287082");
    expect(totp(secret, Math.floor(1111111109 / 30))).toBe("081804");
    expect(totp(secret, Math.floor(2000000000 / 30))).toBe("279037");
  });

  it("accepts one step of clock drift and nothing more", () => {
    const secret = randomBytes(20);
    const t = 1_700_000_000_000;
    const step = Math.floor(t / 30_000);
    expect(matchTotp(secret, totp(secret, step - 1), t)).toBe(step - 1);
    expect(matchTotp(secret, totp(secret, step + 1), t)).toBe(step + 1);
    expect(matchTotp(secret, totp(secret, step - 2), t)).toBeNull();
    expect(matchTotp(secret, "12345", t)).toBeNull();
  });

  it("encrypts secrets when a key is given", () => {
    const s = sealer(randomBytes(32));
    const sealed = s.seal("JBSWY3DPEHPK3PXP");
    expect(sealed).toMatch(/^v1:/);
    expect(sealed).not.toContain("JBSWY3DP");
    expect(s.open(sealed)).toBe("JBSWY3DPEHPK3PXP");
    expect(() => sealer(randomBytes(32)).open(sealed)).toThrow();
    expect(() => sealer().open(sealed)).toThrow(/secrets key/);
  });

  it("makes ten distinct recovery codes", () => {
    const codes = recoveryCodes();
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
  });
});

describe("first start", () => {
  it("offers setup until the owner exists, and the link works once", async () => {
    expect((await app.browser().json("/api/v1/auth/methods")).body).toMatchObject({ passwords: true, setupRequired: true, providers: [] });
    const link = app.auth.setupLink()!;
    const token = new URL(link).searchParams.get("setup")!;
    const b = app.browser();
    const r = await b.json<{ user: { role: string }; mfaSetupRequired: boolean }>("/api/v1/auth/setup", { body: { token, name: "Olivia", email: "Owner@Example.com", password: PASSWORD } });
    expect(r.status).toBe(200);
    expect(r.body.user).toMatchObject({ role: "owner", email: "owner@example.com" });
    expect(r.body.mfaSetupRequired).toBe(true);
    expect(app.auth.setupLink()).toBeUndefined();
    const again = await app.browser().json("/api/v1/auth/setup", { body: { token, name: "Mallory", email: "m@example.com", password: PASSWORD } });
    expect(again.status).toBe(403);
    expect(app.events.map((e) => e.type)).toEqual(["setup", "sign-in"]);
  });

  it("only the latest setup link works", async () => {
    const old = new URL(app.auth.setupLink()!).searchParams.get("setup")!;
    app.auth.setupLink();
    expect((await app.browser().json("/api/v1/auth/setup", { body: { token: old, name: "O", email: "o@example.com", password: PASSWORD } })).status).toBe(403);
  });

  it("refuses short passwords", async () => {
    const token = new URL(app.auth.setupLink()!).searchParams.get("setup")!;
    const r = await app.browser().json<{ detail: string }>("/api/v1/auth/setup", { body: { token, name: "O", email: "o@example.com", password: "short" } });
    expect(r.status).toBe(422);
    expect(r.body.detail).toMatch(/12 to 256/);
  });
});

describe("password sign-in", () => {
  beforeEach(async () => {
    await createOwner(app);
  });

  it("refuses wrong passwords and unknown emails the same way", async () => {
    const wrong = await signIn(app.browser(), "owner@example.com", "wrong password!");
    const unknown = await signIn(app.browser(), "nobody@example.com");
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  it("slows down guessing after ten failures for one email", async () => {
    const b = app.browser();
    for (let i = 0; i < 10; i++) expect((await signIn(b, "owner@example.com", `guess number ${i}`)).status).toBe(401);
    expect((await signIn(b)).status).toBe(429);
    app.clock.t += 15 * 60_000;
    expect((await signIn(b)).status).toBe(200);
  });

  it("makes an owner without a second factor set one up before anything else", async () => {
    const b = app.browser();
    expect((await signIn(b)).body).toMatchObject({ status: "signed-in", mfaSetupRequired: true });
    expect((await needs(b, "viewer")).body.code).toBe("mfa-setup-required");
    expect((await b.json("/api/v1/auth/me")).status).toBe(200);
    await addTotp(app, b);
    expect((await needs(b, "owner")).status).toBe(200);
  });

  it("refuses unsafe requests from other sites", async () => {
    const b = app.browser();
    await signIn(b);
    const r = await b.json("/api/v1/auth/me/totp", { body: {}, headers: { origin: "https://evil.example" } });
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ code: "cross-site" });
    const login = await b.json("/api/v1/auth/login", { body: { email: "owner@example.com", password: PASSWORD }, headers: { origin: "https://evil.example" } });
    expect(login.status).toBe(403);
  });
});

describe("TOTP and recovery codes", () => {
  let secret: string;
  let codes: string[];
  beforeEach(async () => {
    const b = await createOwner(app);
    ({ secret, recoveryCodes: codes } = await addTotp(app, b));
  });

  it("asks for the code after the password, and accepts each code once", async () => {
    const b = app.browser();
    expect((await signIn(b)).body).toEqual({ status: "mfa-required", methods: ["totp", "recovery-code"] });
    expect((await needs(b, "viewer")).status).toBe(401);
    const code = codeAt(secret, app.clock.t);
    expect((await b.json("/api/v1/auth/login/mfa", { body: { code } })).status).toBe(200);
    expect((await needs(b, "owner")).body.kind).toBe("session");

    const other = app.browser();
    await signIn(other);
    expect((await other.json("/api/v1/auth/login/mfa", { body: { code } })).status).toBe(401);
  });

  it("gives up after five wrong codes", async () => {
    const b = app.browser();
    await signIn(b);
    for (let i = 0; i < 5; i++) expect((await b.json("/api/v1/auth/login/mfa", { body: { code: "000000" } })).status).toBe(401);
    expect((await b.json("/api/v1/auth/login/mfa", { body: { code: codeAt(secret, app.clock.t) } })).status).toBe(429);
  });

  it("accepts a recovery code once", async () => {
    const b = app.browser();
    await signIn(b);
    expect((await b.json("/api/v1/auth/login/mfa", { body: { recoveryCode: codes[0]!.toUpperCase() } })).status).toBe(200);
    const again = app.browser();
    await signIn(again);
    expect((await again.json("/api/v1/auth/login/mfa", { body: { recoveryCode: codes[0] } })).status).toBe(401);
    expect((await b.json<{ recoveryCodesLeft: number }>("/api/v1/auth/me")).body.recoveryCodesLeft).toBe(9);
  });

  it("a session opened before the factor existed cannot remove it", async () => {
    const fresh = await startProduct();
    const old = await createOwner(fresh);
    const other = fresh.browser();
    await signIn(other);
    await addTotp(fresh, other);
    const r = await old.json("/api/v1/auth/me/totp", { method: "DELETE" });
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ code: "mfa-required" });
    await fresh.close();
  });

  it("removing a factor works from a session opened with it", async () => {
    const b = app.browser();
    await signIn(b);
    await b.json("/api/v1/auth/login/mfa", { body: { code: codeAt(secret, app.clock.t) } });
    expect((await b.json("/api/v1/auth/me/totp", { method: "DELETE" })).status).toBe(204);
    // Now the owner has no second factor and must set one up again.
    expect((await needs(b, "viewer")).body.code).toBe("mfa-setup-required");
  });

  it("stores the secret encrypted when a key is given", async () => {
    const keyed = await startProduct({ secretsKey: randomBytes(32) });
    const b = await createOwner(keyed);
    const { secret: s } = await addTotp(keyed, b);
    const row = keyed.db.prepare("SELECT secret FROM auth_totp").get() as { secret: string };
    expect(row.secret).toMatch(/^v1:/);
    expect(row.secret).not.toContain(s);
    expect(keyed.auth.secretsInClear).toBe(false);
    await keyed.close();
  });
});

describe("passkeys", () => {
  it("registers a passkey and signs in with it alone", async () => {
    const b = await createOwner(app);
    const key = new SoftPasskey(app.origin);
    const options = (await b.json<{ challenge: string; rp: { id: string } }>("/api/v1/auth/me/passkeys/options", { body: {} })).body;
    const added = await b.json<{ recoveryCodes: string[] }>("/api/v1/auth/me/passkeys", { body: { response: key.register(options), name: "Laptop" } });
    expect(added.status).toBe(201);
    expect(added.body.recoveryCodes).toHaveLength(10);

    const fresh = app.browser();
    const opts = (await fresh.json<{ challenge: string; rpId: string }>("/api/v1/auth/login/passkey/options", { body: {} })).body;
    const r = await fresh.json<{ status: string }>("/api/v1/auth/login/passkey", { body: { response: key.authenticate(opts) } });
    expect(r.body.status).toBe("signed-in");
    expect((await needs(fresh, "owner")).status).toBe(200);
  });

  it("refuses a passkey without user verification when used alone, and a replayed challenge", async () => {
    const b = await createOwner(app);
    const key = new SoftPasskey(app.origin);
    const options = (await b.json<{ challenge: string; rp: { id: string } }>("/api/v1/auth/me/passkeys/options", { body: {} })).body;
    await b.json("/api/v1/auth/me/passkeys", { body: { response: key.register(options) } });

    key.userVerified = false;
    const fresh = app.browser();
    const opts = (await fresh.json<{ challenge: string; rpId: string }>("/api/v1/auth/login/passkey/options", { body: {} })).body;
    expect((await fresh.json("/api/v1/auth/login/passkey", { body: { response: key.authenticate(opts) } })).status).toBe(401);
    // The challenge was used up by the failed attempt.
    key.userVerified = true;
    expect((await fresh.json("/api/v1/auth/login/passkey", { body: { response: key.authenticate(opts) } })).status).toBe(401);
  });

  it("works as the second step after a password, only with that person's passkey", async () => {
    const owner = await createOwner(app);
    await addTotp(app, owner);
    const key = new SoftPasskey(app.origin);
    const options = (await owner.json<{ challenge: string; rp: { id: string } }>("/api/v1/auth/me/passkeys/options", { body: {} })).body;
    await owner.json("/api/v1/auth/me/passkeys", { body: { response: key.register(options) } });

    const b = app.browser();
    expect((await signIn(b)).body.methods).toEqual(["totp", "passkey", "recovery-code"]);
    const opts = (await b.json<{ challenge: string; rpId: string; allowCredentials: unknown[] }>("/api/v1/auth/login/passkey/options", { body: {} })).body;
    expect(opts.allowCredentials).toHaveLength(1);
    key.userVerified = false; // presence is enough as a second factor
    expect((await b.json("/api/v1/auth/login/passkey", { body: { response: key.authenticate(opts) } })).status).toBe(200);
  });
});

describe("sessions", () => {
  let b: Browser;
  beforeEach(async () => {
    b = await createOwner(app);
    await addTotp(app, b);
  });

  it("end after an hour idle and after twelve hours in any case", async () => {
    app.clock.t += 59 * 60_000;
    expect((await needs(b, "viewer")).status).toBe(200);
    app.clock.t += 61 * 60_000;
    expect((await needs(b, "viewer")).status).toBe(401);
  });

  it("end after twelve hours even when used", async () => {
    for (let h = 0; h < 11; h++) {
      app.clock.t += 59 * 60_000;
      expect((await needs(b, "viewer")).status).toBe(200);
    }
    app.clock.t += 60 * 60_000;
    expect((await needs(b, "viewer")).status).toBe(401);
  });

  it("can be listed and revoked, and sign-out ends them", async () => {
    const list = (await b.json<{ sessions: Array<{ id: string; current: boolean }> }>("/api/v1/auth/me/sessions")).body.sessions;
    expect(list).toHaveLength(1);
    expect(list[0]!.current).toBe(true);
    expect((await b.json("/api/v1/auth/logout", { body: {} })).status).toBe(204);
    expect((await needs(b, "viewer")).status).toBe(401);
  });

  it("changing the password signs out every other session", async () => {
    const other = app.browser();
    await signIn(other);
    expect((await b.json("/api/v1/auth/me/password", { body: { currentPassword: PASSWORD, newPassword: "a new long password" } })).status).toBe(204);
    expect((await needs(b, "viewer")).status).toBe(200);
    expect((await other.json("/api/v1/auth/me")).status).toBe(401);
  });
});

describe("members and roles", () => {
  let owner: Browser;
  beforeEach(async () => {
    owner = await createOwner(app);
    await addTotp(app, owner);
  });

  it("invites by link, and the role limits what a member can do", async () => {
    const { browser: viewer } = await invite(app, owner, "vic@example.com", "viewer");
    expect((await needs(viewer, "viewer")).status).toBe(200);
    expect((await needs(viewer, "editor")).body.code).toBe("forbidden");
    expect((await viewer.json("/api/v1/auth/members")).status).toBe(403);
  });

  it("admins cannot make or manage owners", async () => {
    const { browser: admin } = await invite(app, owner, "ada@example.com", "admin");
    await addTotp(app, admin);
    expect((await admin.json("/api/v1/auth/members", { body: { email: "x@example.com", role: "owner" } })).status).toBe(403);
    const members = (await admin.json<{ members: Array<{ id: string; role: string }> }>("/api/v1/auth/members")).body.members;
    const ownerId = members.find((m) => m.role === "owner")!.id;
    expect((await admin.json(`/api/v1/auth/members/${ownerId}`, { method: "PATCH", body: { status: "disabled" } })).status).toBe(403);
  });

  it("keeps at least one owner", async () => {
    const me = (await owner.json<{ user: { id: string } }>("/api/v1/auth/me")).body.user.id;
    expect((await owner.json(`/api/v1/auth/members/${me}`, { method: "PATCH", body: { role: "admin" } })).status).toBe(409);
  });

  it("disabling a member ends their sessions", async () => {
    const { id, browser } = await invite(app, owner, "ed@example.com", "editor");
    expect((await owner.json(`/api/v1/auth/members/${id}`, { method: "PATCH", body: { status: "disabled" } })).status).toBe(200);
    expect((await needs(browser, "viewer")).status).toBe(401);
    expect((await signIn(app.browser(), "ed@example.com")).status).toBe(401);
  });

  it("a reset link sets a new password and can clear second factors", async () => {
    const { id, browser } = await invite(app, owner, "ed@example.com", "editor");
    await addTotp(app, browser);
    const r = await owner.json<{ link: string }>(`/api/v1/auth/members/${id}/reset`, { body: { mfa: true } });
    expect((await needs(browser, "viewer")).status).toBe(401);
    const token = new URL(r.body.link).searchParams.get("link")!;
    const b = app.browser();
    expect((await b.json<{ kind: string }>(`/api/v1/auth/links/${token}`)).body.kind).toBe("reset");
    expect((await b.json(`/api/v1/auth/links/${token}`, { body: { password: "another long password" } })).status).toBe(200);
    expect((await b.json<{ user: { mfa: { totp: boolean } } }>("/api/v1/auth/me")).body.user.mfa.totp).toBe(false);
    expect((await b.json(`/api/v1/auth/links/${token}`, { body: { password: "and yet another one" } })).status).toBe(404);
  });
});

describe("API tokens", () => {
  let owner: Browser;
  beforeEach(async () => {
    owner = await createOwner(app);
    await addTotp(app, owner);
  });

  const bearer = (token: string, role = "viewer") => fetch(`${app.origin}/api/v1/needs/${role}`, { headers: { authorization: `Bearer ${token}` } });

  it("are shown once, limited to their role and expire", async () => {
    const r = await owner.json<{ token: string; id: string }>("/api/v1/auth/tokens", { body: { name: "CI", role: "editor", expiresInDays: 1 } });
    expect(r.status).toBe(201);
    expect(r.body.token).toMatch(/^oa_test_/);
    expect((await bearer(r.body.token, "editor")).status).toBe(200);
    expect((await bearer(r.body.token, "admin")).status).toBe(403);
    const list = (await owner.json<{ tokens: Array<Record<string, unknown>> }>("/api/v1/auth/tokens")).body.tokens;
    expect(JSON.stringify(list)).not.toContain(r.body.token);
    app.clock.t += 86_400_000;
    expect((await bearer(r.body.token, "viewer")).status).toBe(401);
  });

  it("can be revoked, and cannot create tokens or exceed their creator", async () => {
    const r = await owner.json<{ token: string; id: string }>("/api/v1/auth/tokens", { body: { name: "CI", role: "admin" } });
    const viaToken = await fetch(`${app.origin}/api/v1/auth/tokens`, { method: "POST", headers: { authorization: `Bearer ${r.body.token}`, "content-type": "application/json" }, body: JSON.stringify({ name: "x", role: "admin" }) });
    expect(viaToken.status).toBe(403);
    expect((await owner.json(`/api/v1/auth/tokens/${r.body.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await bearer(r.body.token)).status).toBe(401);
    expect((await owner.json("/api/v1/auth/tokens", { body: { name: "x", role: "owner" } })).status).toBe(422);

    const { browser: editorUser } = await invite(app, owner, "ed@example.com", "editor");
    expect((await editorUser.json("/api/v1/auth/tokens", { body: { name: "x", role: "editor" } })).status).toBe(403);
  });

  it("refuses bearer tokens that are not API tokens", async () => {
    expect((await bearer("some-shared-secret")).status).toBe(401);
  });
});

describe("OIDC", () => {
  let idp: Awaited<ReturnType<typeof startIdp>>;
  beforeEach(async () => {
    idp = await startIdp();
  });
  afterEach(() => idp.close());

  async function withProvider(extra: Record<string, unknown> = {}) {
    await app.close();
    app = await startProduct({ oidc: [{ id: "corp", name: "Corp SSO", issuer: idp.issuer, clientId: "vulns", clientSecret: "s3cret", allowInsecure: true, ...extra }] });
    return app;
  }

  it("lists providers and refuses people nobody invited", async () => {
    await withProvider();
    expect((await app.browser().json<{ providers: unknown[] }>("/api/v1/auth/methods")).body.providers).toEqual([{ id: "corp", name: "Corp SSO" }]);
    idp.next = { sub: "u1", email: "stranger@example.com", email_verified: true };
    const r = await oidcSignIn(app.browser(), "corp");
    expect(r.status).toBe(302);
    expect(decodeURIComponent(r.location)).toMatch(/auth_error=You have no access/);
  });

  it("signs in an invited person by verified email, and returns to the page they asked for", async () => {
    await withProvider();
    const owner = await createOwner(app);
    await addTotp(app, owner);
    await owner.json("/api/v1/auth/members", { body: { email: "ed@example.com", role: "editor" } });
    idp.next = { sub: "u1", email: "ED@example.com", email_verified: true, name: "Ed" };
    const b = app.browser();
    const r = await oidcSignIn(b, "corp", "/#/assets");
    expect(r.location).toBe("/#/assets");
    const me = (await b.json<{ user: { role: string; status: string; providers: string[] } }>("/api/v1/auth/me")).body.user;
    expect(me).toMatchObject({ role: "editor", status: "active", providers: ["corp"] });
  });

  it("does not link by an unverified email", async () => {
    await withProvider();
    await createOwner(app);
    idp.next = { sub: "attacker", email: "owner@example.com", email_verified: false };
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/auth_error=/);
  });

  it("maps groups to roles on every sign-in", async () => {
    await withProvider({ scopes: ["openid", "email", "groups"], roleMapping: { "vulns-admins": "admin", "vulns-readers": "viewer" } });
    idp.next = { sub: "u2", email: "ann@example.com", email_verified: true, groups: ["staff", "vulns-readers"] };
    const b = app.browser();
    await oidcSignIn(b, "corp");
    expect((await needs(b, "viewer")).status).toBe(200);
    expect((await needs(b, "admin")).status).toBe(403);

    idp.next = { sub: "u2", email: "ann@example.com", email_verified: true, groups: ["vulns-admins"] };
    const again = app.browser();
    await oidcSignIn(again, "corp");
    // An admin from the IdP does not need a local second factor: the IdP enforces its own.
    expect((await needs(again, "admin")).status).toBe(200);

    idp.next = { sub: "u2", email: "ann@example.com", email_verified: true, groups: ["staff"] };
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/none of the groups/);
  });

  it("only allows listed domains", async () => {
    await withProvider({ defaultRole: "viewer", allowedDomains: ["example.com"] });
    idp.next = { sub: "u3", email: "eve@evil.test", email_verified: true };
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/not in an allowed domain/);
    idp.next = { sub: "u4", email: "amy@example.com", email_verified: true };
    expect((await oidcSignIn(app.browser(), "corp")).location).toBe("/");
  });

  it("refuses a callback without the state cookie, and ID tokens for someone else", async () => {
    await withProvider({ defaultRole: "viewer" });
    idp.next = { sub: "u5", email: "bo@example.com", email_verified: true };
    const attacker = app.browser();
    const start = await attacker.fetch("/api/v1/auth/oidc/corp/start");
    const atIdp = await fetch(start.headers.get("location")!, { redirect: "manual" });
    const callback = new URL(atIdp.headers.get("location")!);
    // The victim's browser never started this sign-in.
    const victim = app.browser();
    const r = await victim.fetch(callback.pathname + callback.search);
    expect(decodeURIComponent(r.headers.get("location")!)).toMatch(/another browser/);
    expect((await needs(victim, "viewer")).status).toBe(401);

    idp.tamper = "audience";
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/could not be verified/);
    idp.tamper = "nonce";
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/could not be verified/);
  });

  it("reads groups from nested claims and from role objects", async () => {
    await withProvider({ groupsClaim: "realm_access.roles", roleMapping: { "ops-admin": "admin" } });
    idp.next = { sub: "k1", email: "kim@example.com", email_verified: true, realm_access: { roles: ["offline_access", "ops-admin"] } };
    const b = app.browser();
    await oidcSignIn(b, "corp");
    expect((await needs(b, "admin")).status).toBe(200);

    await withProvider({ groupsClaim: "urn:zitadel:iam:org:project:roles", roleMapping: { editor: "editor" } });
    idp.next = { sub: "z1", email: "zoe@example.com", email_verified: true, "urn:zitadel:iam:org:project:roles": { editor: { "123": "acme.zitadel.cloud" } } };
    const z = app.browser();
    await oidcSignIn(z, "corp");
    expect((await needs(z, "editor")).status).toBe(200);
  });

  it("reads groups from userinfo when the ID token has none", async () => {
    idp.userinfo = { sub: "u7", groups: ["vulns-admins"] };
    await withProvider({ roleMapping: { "vulns-admins": "admin" } });
    idp.next = { sub: "u7", email: "una@example.com", email_verified: true };
    const b = app.browser();
    await oidcSignIn(b, "corp");
    expect((await needs(b, "admin")).status).toBe(200);
  });

  it("refuses when the provider left the groups out of the token", async () => {
    await withProvider({ roleMapping: { "vulns-admins": "admin" } });
    idp.next = { sub: "u8", email: "max@example.com", email_verified: true, _claim_names: { groups: "src1" }, _claim_sources: { src1: { endpoint: "https://graph.example" } } };
    expect(decodeURIComponent((await oidcSignIn(app.browser(), "corp")).location)).toMatch(/left your groups out of the token/);
  });

  it("makes the first person the owner through a provider, with the setup link", async () => {
    await app.close();
    app = await startProduct({ passwords: false, oidc: [{ id: "corp", name: "Corp SSO", issuer: idp.issuer, clientId: "vulns", clientSecret: "s3cret", allowInsecure: true }] });
    const token = new URL(app.auth.setupLink()!).searchParams.get("setup")!;
    // A password owner could never sign in with passwords off.
    const pw = await app.browser().json<{ detail: string }>("/api/v1/auth/setup", { body: { token, name: "O", email: "o@example.com", password: PASSWORD } });
    expect(pw.status).toBe(409);
    expect(pw.body.detail).toMatch(/continue with Corp SSO/);
    expect((await app.browser().fetch("/api/v1/auth/oidc/corp/start?setup=wrong")).status).toBe(403);

    idp.next = { sub: "first", email: "olivia@example.com", email_verified: true, name: "Olivia" };
    const b = app.browser();
    const start = await b.fetch(`/api/v1/auth/oidc/corp/start?setup=${token}`);
    const atIdp = await fetch(start.headers.get("location")!, { redirect: "manual" });
    const back = new URL(atIdp.headers.get("location")!);
    expect((await b.fetch(back.pathname + back.search)).headers.get("location")).toBe("/");
    expect((await b.json<{ user: { role: string; email: string; providers: string[] } }>("/api/v1/auth/me")).body.user).toMatchObject({ role: "owner", email: "olivia@example.com", providers: ["corp"] });
    expect(app.events.find((e) => e.type === "setup")).toMatchObject({ method: "oidc:corp" });
    // The link is used: nobody else becomes owner with it.
    expect(app.auth.setupLink()).toBeUndefined();
    expect((await app.browser().fetch(`/api/v1/auth/oidc/corp/start?setup=${token}`)).status).toBe(403);
  });

  it("never redirects to another site after sign-in", async () => {
    await withProvider({ defaultRole: "viewer" });
    idp.next = { sub: "u6", email: "cy@example.com", email_verified: true };
    expect((await oidcSignIn(app.browser(), "corp", "//evil.example/x")).location).toBe("/");
  });
});

describe("providers under Settings", () => {
  let idp: Awaited<ReturnType<typeof startIdp>>;
  let owner: Browser;
  beforeEach(async () => {
    idp = await startIdp();
    await app.close();
    app = await startProduct({ allowInsecureIssuers: true, secretsKey: randomBytes(32), oidc: [{ id: "env-sso", name: "Env", issuer: "https://env.example.com", clientId: "c" }] });
    owner = await createOwner(app);
    await addTotp(app, owner);
  });
  afterEach(() => idp.close());

  const add = (b: Browser, body: Record<string, unknown>) => b.json<Record<string, unknown>>("/api/v1/auth/providers", { body });
  const keycloak = () => ({ preset: "keycloak", issuer: idp.issuer, clientId: "vulns", clientSecret: "s3cret", groupsClaim: "realm_access.roles", roleMapping: { "ops-admin": "admin" } });

  it("adds a provider from a preset, keeps its secret sealed, and signs people in with it", async () => {
    const r = await add(owner, keycloak());
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ id: "keycloak", name: "Keycloak", source: "settings", hasClientSecret: true, scopes: ["openid", "email", "profile"], redirectUri: `${app.origin}/api/v1/auth/oidc/keycloak/callback` });
    expect(JSON.stringify(r.body)).not.toContain("s3cret");
    const stored = app.db.prepare("SELECT client_secret FROM auth_providers WHERE id = 'keycloak'").get() as { client_secret: string };
    expect(stored.client_secret).toMatch(/^v1:/);

    const methods = (await app.browser().json<{ providers: unknown[] }>("/api/v1/auth/methods")).body.providers;
    expect(methods).toEqual([{ id: "env-sso", name: "Env" }, { id: "keycloak", name: "Keycloak" }]);
    idp.next = { sub: "k1", email: "kim@example.com", email_verified: true, realm_access: { roles: ["ops-admin"] } };
    const b = app.browser();
    expect((await oidcSignIn(b, "keycloak")).location).toBe("/");
    expect((await needs(b, "admin")).status).toBe(200);

    const list = (await owner.json<{ providers: Array<{ id: string; source: string }>; redirectUriTemplate: string }>("/api/v1/auth/providers")).body;
    expect(list.providers.map((p) => `${p.id}:${p.source}`)).toEqual(["env-sso:environment", "keycloak:settings"]);
    expect(list.redirectUriTemplate).toBe(`${app.origin}/api/v1/auth/oidc/{id}/callback`);
  });

  it("lets admins see providers but only owners change them", async () => {
    const { browser: admin } = await invite(app, owner, "ada@example.com", "admin");
    await addTotp(app, admin);
    expect((await admin.json("/api/v1/auth/providers")).status).toBe(200);
    expect((await add(admin, keycloak())).status).toBe(403);
    expect((await admin.json("/api/v1/auth/providers/discover", { body: { issuer: idp.issuer } })).status).toBe(403);
  });

  it("checks what it is given", async () => {
    expect((await add(owner, { ...keycloak(), preset: "myspace" })).status).toBe(422);
    expect((await add(owner, { ...keycloak(), scopes: ["email"] })).status).toBe(422);
    expect((await add(owner, { ...keycloak(), roleMapping: { ops: "god" } })).status).toBe(422);
    expect((await add(owner, { ...keycloak(), id: "Bad Id" })).status).toBe(422);
    expect((await add(owner, { ...keycloak(), id: "env-sso" })).status).toBe(409);
    expect((await add(owner, keycloak())).status).toBe(201);
    expect((await add(owner, keycloak())).status).toBe(409);
    expect((await owner.json("/api/v1/auth/providers/env-sso", { method: "PATCH", body: { name: "x" } })).status).toBe(409);
  });

  it("sends the sign-in screen straight to one provider, and refuses a second", async () => {
    const methods = async () => (await app.browser().json<{ autoRedirect: string | null }>("/api/v1/auth/methods")).body.autoRedirect;
    expect(await methods()).toBeNull();
    const r = await add(owner, { ...keycloak(), autoRedirect: true });
    expect(r.body).toMatchObject({ id: "keycloak", autoRedirect: true });
    expect(await methods()).toBe("keycloak");
    const other = await add(owner, { ...keycloak(), id: "second", autoRedirect: true });
    expect(other.status).toBe(409);
    expect(JSON.stringify(other.body)).toContain("already goes straight to Keycloak");
    expect((await add(owner, { ...keycloak(), id: "second" })).status).toBe(201);
    expect((await owner.json("/api/v1/auth/providers/second", { method: "PATCH", body: { autoRedirect: true } })).status).toBe(409);
    expect((await owner.json("/api/v1/auth/providers/keycloak", { method: "PATCH", body: { autoRedirect: "yes" } })).status).toBe(422);
    // Turned off, the provider is not on the sign-in screen, so nothing goes straight to it.
    expect((await owner.json("/api/v1/auth/providers/keycloak", { method: "PATCH", body: { enabled: false } })).body).toMatchObject({ autoRedirect: true });
    expect(await methods()).toBeNull();
    expect((await owner.json("/api/v1/auth/providers/keycloak", { method: "PATCH", body: { enabled: true, autoRedirect: false } })).status).toBe(200);
    expect((await owner.json("/api/v1/auth/providers/second", { method: "PATCH", body: { autoRedirect: true } })).status).toBe(200);
    expect(await methods()).toBe("second");
  });

  it("forgets who signed in through a provider when it is removed or points elsewhere", async () => {
    await add(owner, { ...keycloak(), roleMapping: {}, defaultRole: "viewer" });
    idp.next = { sub: "same-sub", email: "kim@example.com", email_verified: true };
    await oidcSignIn(app.browser(), "keycloak");
    const linked = () => (app.db.prepare("SELECT COUNT(*) AS n FROM auth_identities WHERE provider = 'keycloak'").get() as { n: number }).n;
    expect(linked()).toBe(1);

    const patched = await owner.json<Record<string, unknown>>("/api/v1/auth/providers/keycloak", { method: "PATCH", body: { name: "Ops SSO", issuer: `${idp.issuer}/` } });
    expect(patched.body).toMatchObject({ name: "Ops SSO", hasClientSecret: true });
    expect(linked()).toBe(0);
    expect(app.events.map((e) => e.type)).toContain("provider-updated");

    await owner.json("/api/v1/auth/providers/keycloak", { method: "PATCH", body: { issuer: idp.issuer, enabled: false } });
    expect((await app.browser().json<{ providers: unknown[] }>("/api/v1/auth/methods")).body.providers).toEqual([{ id: "env-sso", name: "Env" }]);
    expect((await owner.json("/api/v1/auth/providers/keycloak", { method: "DELETE" })).status).toBe(204);
    expect((await owner.json("/api/v1/auth/providers/keycloak", { method: "DELETE" })).status).toBe(404);
  });

  it("reads a discovery document before saving", async () => {
    const ok = await owner.json<Record<string, unknown>>("/api/v1/auth/providers/discover", { body: { issuer: idp.issuer } });
    expect(ok.body).toMatchObject({ issuer: idp.issuer, pkce: true });
    const wrong = await owner.json<{ detail: string }>("/api/v1/auth/providers/discover", { body: { issuer: "http://127.0.0.1:9/realms/x" } });
    expect(wrong.status).toBe(422);
    expect(wrong.body.detail).toMatch(/No OpenID provider answers/);
  });
});

describe("the user role", () => {
  it("is refused where the product has not turned it on", async () => {
    const owner = await createOwner(app);
    await addTotp(app, owner);
    const r = await owner.json<{ detail: string }>("/api/v1/auth/members", { body: { email: "u@example.com", role: "user" } });
    expect(r.status).toBe(422);
    expect(r.body.detail).toBe("role must be owner, admin, editor or viewer.");
    expect((await app.browser().json<{ users: boolean }>("/api/v1/auth/methods")).body.users).toBe(false);
    await expect(startProduct({ oidc: [{ id: "x", name: "X", issuer: "https://x.example.com", clientId: "c", defaultRole: "user" }] })).rejects.toThrow(/needs users: true/);
  });

  it("signs people in to their own account only, where the product turns it on", async () => {
    await app.close();
    app = await startProduct({ users: true });
    const owner = await createOwner(app);
    await addTotp(app, owner);
    expect((await app.browser().json<{ users: boolean }>("/api/v1/auth/methods")).body.users).toBe(true);
    const { browser: u } = await invite(app, owner, "uma@example.com", "user");
    const me = await u.json<{ user: { role: string }; mfaSetupRequired: boolean }>("/api/v1/auth/me");
    expect(me.body).toMatchObject({ user: { role: "user" }, mfaSetupRequired: false });
    expect((await needs(u, "viewer")).status).toBe(403);
    expect((await u.json("/api/v1/auth/me/sessions")).status).toBe(200);
    expect((await u.json("/api/v1/auth/members")).status).toBe(403);
  });

  it("tells the product which groups someone came with", async () => {
    const idp = await startIdp();
    const seen: unknown[] = [];
    await app.close();
    app = await startProduct({ users: true, onOidcSignIn: (s) => seen.push(s), oidc: [{ id: "corp", name: "Corp", issuer: idp.issuer, clientId: "c", allowInsecure: true, defaultRole: "user" }] });
    idp.next = { sub: "s1", email: "gus@example.com", email_verified: true, groups: ["eng", "oncall"] };
    const b = app.browser();
    await oidcSignIn(b, "corp");
    expect((await b.json<{ user: { role: string; id: string } }>("/api/v1/auth/me")).body.user.role).toBe("user");
    expect(seen).toEqual([{ userId: expect.any(String), provider: "corp", groups: ["eng", "oncall"] }]);
    await idp.close();
  });

  it("keeps everything when 0.2.0 data is migrated", async () => {
    const { DatabaseSync } = await import("node:sqlite");
    const { migrate } = await import("../src/db.ts");
    const db = new DatabaseSync(":memory:");
    migrate(db, 3);
    const t = "2026-10-01T00:00:00.000Z";
    db.prepare("INSERT INTO auth_users (id, email, name, role, status, password_hash, created_at) VALUES ('u1', 'o@example.com', 'O', 'owner', 'active', 'h', ?)").run(t);
    db.prepare("INSERT INTO auth_sessions (id_hash, id, user_id, method, created_at, last_seen_at, expires_at) VALUES ('h1', 's1', 'u1', 'password', ?, ?, ?)").run(t, t, t);
    db.prepare("INSERT INTO auth_identities (provider, subject, user_id, created_at) VALUES ('corp', 'sub', 'u1', ?)").run(t);
    db.prepare("INSERT INTO auth_recovery_codes (user_id, code_hash) VALUES ('u1', 'c1')").run();
    db.prepare("INSERT INTO auth_tokens (id, secret_hash, name, role, created_by, created_at, expires_at) VALUES ('t1', 'x', 'CI', 'admin', 'u1', ?, ?)").run(t, t);
    db.prepare("INSERT INTO auth_providers (id, preset, name, issuer, client_id, scopes, default_role, created_at, updated_at) VALUES ('kc', 'keycloak', 'KC', 'https://kc', 'c', '[]', 'viewer', ?, ?)").run(t, t);
    migrate(db);
    const count = (table: string) => (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;
    expect(["auth_users", "auth_sessions", "auth_identities", "auth_recovery_codes", "auth_tokens", "auth_providers"].map(count)).toEqual([1, 1, 1, 1, 1, 1]);
    expect(db.prepare("SELECT default_role FROM auth_providers").get()).toEqual({ default_role: "viewer" });
    expect(db.prepare("PRAGMA foreign_keys").get()).toEqual({ foreign_keys: 1 });
    db.prepare("INSERT INTO auth_users (id, email, name, role, status, created_at) VALUES ('u2', 'u@example.com', 'U', 'user', 'active', ?)").run(t);
    // The references still work: removing the owner removes their sessions and identities, and keeps their token.
    db.prepare("DELETE FROM auth_users WHERE id = 'u1'").run();
    expect([count("auth_sessions"), count("auth_identities"), count("auth_tokens")]).toEqual([0, 0, 1]);
    expect(db.prepare("SELECT created_by FROM auth_tokens").get()).toEqual({ created_by: null });
  });
});

describe("which second factor opened a session", () => {
  type Me = { session: { method: string; factor: string | null }; passwordManagedBy: string | null };
  it("is kept for a code, a passkey and a recovery code, and when a factor is added", async () => {
    const owner = await createOwner(app);
    expect((await owner.json<Me>("/api/v1/auth/me")).body.session).toMatchObject({ method: "password", factor: null });
    const { secret, recoveryCodes } = await addTotp(app, owner);
    expect((await owner.json<Me>("/api/v1/auth/me")).body.session.factor).toBe("totp");

    const withCode = app.browser();
    await signIn(withCode);
    await withCode.json("/api/v1/auth/login/mfa", { body: { code: codeAt(secret, app.clock.t) } });
    expect((await withCode.json<Me>("/api/v1/auth/me")).body.session).toMatchObject({ method: "password", factor: "totp" });

    const withRecovery = app.browser();
    await signIn(withRecovery);
    await withRecovery.json("/api/v1/auth/login/mfa", { body: { recoveryCode: recoveryCodes[0] } });
    expect((await withRecovery.json<Me>("/api/v1/auth/me")).body.session.factor).toBe("recovery-code");

    const key = new SoftPasskey(app.origin);
    const options = (await owner.json<{ challenge: string; rp: { id: string } }>("/api/v1/auth/me/passkeys/options", { body: {} })).body;
    await owner.json("/api/v1/auth/me/passkeys", { body: { response: key.register(options) } });
    expect((await owner.json<Me>("/api/v1/auth/me")).body.session.factor).toBe("passkey");
    const alone = app.browser();
    const opts = (await alone.json<{ challenge: string; rpId: string }>("/api/v1/auth/login/passkey/options", { body: {} })).body;
    await alone.json("/api/v1/auth/login/passkey", { body: { response: key.authenticate(opts) } });
    expect((await alone.json<Me>("/api/v1/auth/me")).body.session).toMatchObject({ method: "passkey", factor: "passkey" });
  });
});

describe("passwords another directory keeps", () => {
  it("checks them there, and never takes one here", async () => {
    let managed = "";
    await app.close();
    app = await startProduct({
      externalPasswords: { managedBy: (id) => (id === managed ? "Active Directory" : undefined), verify: async (_id, pw) => pw === "the AD password" },
    });
    const owner = await createOwner(app);
    await addTotp(app, owner);
    const { id, browser } = await invite(app, owner, "dee@example.com", "viewer");
    managed = id;
    type Me = { passwordManagedBy: string | null };
    expect((await browser.json<Me>("/api/v1/auth/me")).body.passwordManagedBy).toBe("Active Directory");

    // The password set with the invitation no longer works: Active Directory decides.
    expect((await app.browser().json("/api/v1/auth/login", { body: { email: "dee@example.com", password: PASSWORD } })).status).toBe(401);
    const b = app.browser();
    expect((await b.json<{ status: string }>("/api/v1/auth/login", { body: { email: "dee@example.com", password: "the AD password" } })).body.status).toBe("signed-in");

    expect((await b.json<{ detail: string }>("/api/v1/auth/me/password", { body: { currentPassword: "x", newPassword: "a brand new password" } })).body.detail).toMatch(/kept in Active Directory/);
    expect((await owner.json(`/api/v1/auth/members/${id}/reset`, { body: {} })).status).toBe(409);
    expect((await owner.json<{ link: string | null }>(`/api/v1/auth/members/${id}/reset`, { body: { mfa: true } })).body).toEqual({ link: null, linkExpiresAt: null });
  });
});

describe("environment", () => {
  it("reads one OIDC provider with role mapping", async () => {
    const { oidcFromEnv } = await import("../src/env.ts");
    expect(oidcFromEnv({})).toEqual([]);
    const [p] = oidcFromEnv({ OPENASY_OIDC_ISSUER: "https://login.example.com", OPENASY_OIDC_CLIENT_ID: "vulns", OPENASY_OIDC_ROLE_MAPPING: "sec=admin, staff=viewer", OPENASY_OIDC_ALLOWED_DOMAINS: "Example.com" });
    expect(p).toMatchObject({ id: "sso", name: "SSO", roleMapping: { sec: "admin", staff: "viewer" }, allowedDomains: ["example.com"] });
    expect(() => oidcFromEnv({ OPENASY_OIDC_ISSUER: "https://x" })).toThrow(/OPENASY_OIDC_CLIENT_ID/);
    expect(() => oidcFromEnv({ OPENASY_OIDC_ISSUER: "https://x", OPENASY_OIDC_CLIENT_ID: "c", OPENASY_OIDC_DEFAULT_ROLE: "god" })).toThrow(/not owner/);
  });

  it("takes a provider's defaults from OIDC_PROVIDER, and the variables still win", async () => {
    const { oidcFromEnv } = await import("../src/env.ts");
    const base = { OPENASY_OIDC_ISSUER: "https://okta.example.com", OPENASY_OIDC_CLIENT_ID: "vpn" };
    expect(oidcFromEnv({ ...base, OPENASY_OIDC_PROVIDER: "okta" })[0]).toMatchObject({ name: "Okta", scopes: ["openid", "email", "profile", "groups"], groupsClaim: "groups" });
    expect(oidcFromEnv({ ...base, OPENASY_OIDC_PROVIDER: "keycloak", OPENASY_OIDC_NAME: "Ops", OPENASY_OIDC_GROUPS_CLAIM: "realm_access.roles" })[0]).toMatchObject({ name: "Ops", groupsClaim: "realm_access.roles" });
    expect(() => oidcFromEnv({ ...base, OPENASY_OIDC_PROVIDER: "myspace" })).toThrow(/is not one of keycloak, entra/);
  });

  it("still reads the names with the product's prefix, warns, and lets the shared names win", async () => {
    const { oidcFromEnv } = await import("../src/env.ts");
    const warnings: string[] = [];
    const listen = (w: Error) => warnings.push(w.message);
    process.on("warning", listen);
    try {
      const [p] = oidcFromEnv({ VPN_OIDC_ISSUER: "https://old.example.com", VPN_OIDC_CLIENT_ID: "vpn", OPENASY_OIDC_ISSUER: "https://id.example.com", VPN_OIDC_ROLE_MAPPING: "ops=admin" }, "VPN_");
      expect(p).toMatchObject({ issuer: "https://id.example.com", clientId: "vpn", roleMapping: { ops: "admin" } });
      expect(oidcFromEnv({ VPN_OIDC_ISSUER: "https://old.example.com", VPN_OIDC_CLIENT_ID: "vpn" })).toEqual([]);
      await new Promise((r) => setImmediate(r));
      expect(warnings).toEqual(["Rename these variables, the old names go in a later release: VPN_OIDC_CLIENT_ID -> OPENASY_OIDC_CLIENT_ID, VPN_OIDC_ROLE_MAPPING -> OPENASY_OIDC_ROLE_MAPPING"]);
    } finally {
      process.off("warning", listen);
    }
  });

  it("goes straight to the provider with OPENASY_OIDC_AUTO_REDIRECT", async () => {
    const { oidcFromEnv } = await import("../src/env.ts");
    const base = { OPENASY_OIDC_ISSUER: "https://id.example.com", OPENASY_OIDC_CLIENT_ID: "vpn" };
    expect(oidcFromEnv(base)[0]!.autoRedirect).toBeUndefined();
    expect(oidcFromEnv({ ...base, OPENASY_OIDC_AUTO_REDIRECT: "false" })[0]!.autoRedirect).toBeUndefined();
    expect(oidcFromEnv({ ...base, OPENASY_OIDC_AUTO_REDIRECT: "true" })[0]!.autoRedirect).toBe(true);
    expect(() => oidcFromEnv({ ...base, OPENASY_OIDC_AUTO_REDIRECT: "yes" })).toThrow(/true or false/);
    expect(oidcFromEnv({ OPENASY_OIDC_AUTO_REDIRECT: "true" })).toEqual([]);

    await app.close();
    app = await startProduct({ secretsKey: randomBytes(32), oidc: [{ id: "sso", name: "Identity", issuer: "https://id.example.com", clientId: "c", autoRedirect: true }] });
    const owner = await createOwner(app);
    await addTotp(app, owner);
    expect((await app.browser().json("/api/v1/auth/methods")).body).toMatchObject({ autoRedirect: "sso" });
    expect((await owner.json("/api/v1/auth/providers", { body: { preset: "keycloak", id: "kc", issuer: "https://kc.example.com", clientId: "c", autoRedirect: true } })).status).toBe(409);
  });

  it("has setup steps with the redirect address for every preset", async () => {
    const { PRESETS } = await import("../src/presets.ts");
    expect(new Set(PRESETS.map((p) => p.id)).size).toBe(PRESETS.length);
    for (const p of PRESETS) {
      expect(p.steps.join(" "), p.id).toContain("{redirectUri}");
      expect(p.scopes, p.id).toContain("openid");
      expect(p.docs, p.id).toMatch(/^https:\/\//);
    }
  });

  it("reads the secrets key as hex, base64 or raw bytes", async () => {
    const { readSecretsKey } = await import("../src/env.ts");
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "auth-key-"));
    const key = randomBytes(32);
    for (const [name, content] of [["hex", key.toString("hex") + "\n"], ["b64", key.toString("base64")], ["raw", key]] as const) {
      writeFileSync(join(dir, name), content);
      expect(readSecretsKey(join(dir, name))).toEqual(key);
    }
    writeFileSync(join(dir, "short"), "abcd");
    expect(() => readSecretsKey(join(dir, "short"))).toThrow(/32-byte/);
    expect(readSecretsKey(join(dir, "missing"))).toBeUndefined();
  });
});

describe("device binding", () => {
  it("keeps the session across a browser update but ends it on another device", async () => {
    const b = await createOwner(app);
    await addTotp(app, b);
    const ua = (v: string, os = "Macintosh; Intel Mac OS X 10_15_7") => ({ "user-agent": `Mozilla/5.0 (${os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v} Safari/537.36` });
    // The session was opened without a User-Agent by the test client; sign in again with one.
    await b.json("/api/v1/auth/logout", { body: {} });
    await b.json("/api/v1/auth/login", { body: { email: "owner@example.com", password: PASSWORD }, headers: ua("130.0.0.0") });
    const code = (await b.json<{ status: string }>("/api/v1/auth/me", { headers: ua("130.0.0.0") })).status;
    expect(code).toBe(401); // still at the second step
    app.clock.t += 30_000;
    const secret = (app.db.prepare("SELECT secret FROM auth_totp").get() as { secret: string }).secret.slice(6);
    expect((await b.json("/api/v1/auth/login/mfa", { body: { code: codeAt(secret, app.clock.t) }, headers: ua("130.0.0.0") })).status).toBe(200);
    expect((await b.json("/api/v1/needs/viewer", { headers: ua("131.0.6778.86") })).status).toBe(200);
    expect((await b.json("/api/v1/needs/viewer", { headers: ua("131.0.6778.86", "Windows NT 10.0; Win64; x64") })).status).toBe(401);
    // Ended for good, also back on the original browser.
    expect((await b.json("/api/v1/needs/viewer", { headers: ua("131.0.6778.86") })).status).toBe(401);
    expect(app.events.some((e) => e.type === "session-ended")).toBe(true);
  });
});
