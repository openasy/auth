import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authOpenApi } from "../src/openapi.ts";
import { addTotp, codeAt, createOwner, PASSWORD, SoftPasskey, startIdp, startProduct, type Browser } from "./helpers.ts";

// Contract tests (ADR 0024): every response under /api/v1/auth matches authOpenApi(), and every operation is called.

const fragment = authOpenApi();
const spec = { openapi: "3.1.1", info: { title: "auth", version: "0" }, ...fragment };
const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");
const covered = new Set<string>();

type Paths = Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, unknown> }> }>>;

async function check(b: Browser, method: string, path: string, concrete = path, body?: unknown, headers?: Record<string, string>) {
  const res = await b.fetch(concrete, { method, body, headers });
  const operation = (spec.paths as Paths)[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not described`).toBeDefined();
  covered.add(`${method} ${path}`);
  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which is not described`).toBeDefined();
  const at = declared!.$ref
    ? `openapi#/components/responses/AuthProblem`
    : `openapi#/paths/${path.replaceAll("~", "~0").replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;
  const response = declared!.$ref ? fragment.components.responses.AuthProblem : declared!;
  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { status: res.status, body: undefined as never, headers: res.headers };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect((response.content as Record<string, unknown>)[type], `${method} ${path} ${res.status} sent ${type}`).toBeDefined();
  const data = await res.json();
  const validate = ajv.getSchema(`${at}/content/${type.replace("/", "~1")}/schema`)!;
  expect(validate(data), `${method} ${concrete} ${res.status}: ${JSON.stringify(validate.errors)}`).toBe(true);
  return { status: res.status, body: data, headers: res.headers };
}

let app: Awaited<ReturnType<typeof startProduct>>;
let idp: Awaited<ReturnType<typeof startIdp>>;

beforeAll(async () => {
  idp = await startIdp();
  app = await startProduct({ oidc: [{ id: "corp", name: "Corp", issuer: idp.issuer, clientId: "c", clientSecret: "s", allowInsecure: true, defaultRole: "viewer" }] });
});
afterAll(async () => {
  await app.close();
  await idp.close();
});

describe("/api/v1/auth matches its OpenAPI description", () => {
  it("first start, sign-in and the second step", async () => {
    const anon = app.browser();
    await check(anon, "GET", "/api/v1/auth/methods");
    await check(anon, "POST", "/api/v1/auth/setup", undefined, { token: "wrong", name: "O", email: "o@example.com", password: PASSWORD });
    await check(anon, "POST", "/api/v1/auth/login", undefined, { email: "nobody@example.com", password: "x" });
    await check(anon, "GET", "/api/v1/auth/me");

    const token = new URL(app.auth.setupLink()!).searchParams.get("setup");
    const owner = app.browser();
    expect((await check(owner, "POST", "/api/v1/auth/setup", undefined, { token, name: "Olivia", email: "owner@example.com", password: PASSWORD })).status).toBe(200);
    const { secret } = (await check(owner, "POST", "/api/v1/auth/me/totp")).body as { secret: string };
    await check(owner, "POST", "/api/v1/auth/me/totp/confirm", undefined, { code: "000000" });
    expect((await check(owner, "POST", "/api/v1/auth/me/totp/confirm", undefined, { code: codeAt(secret, app.clock.t) })).status).toBe(200);
    app.clock.t += 30_000;
    await check(owner, "POST", "/api/v1/auth/me/recovery-codes");

    const b = app.browser();
    expect((await check(b, "POST", "/api/v1/auth/login", undefined, { email: "owner@example.com", password: PASSWORD })).body).toMatchObject({ status: "mfa-required" });
    await check(b, "POST", "/api/v1/auth/login/mfa", undefined, { code: "000000" });
    expect((await check(b, "POST", "/api/v1/auth/login/mfa", undefined, { code: codeAt(secret, app.clock.t) })).status).toBe(200);
    await check(b, "POST", "/api/v1/auth/logout");
    await check(b, "POST", "/api/v1/auth/login/passkey", undefined, { response: { id: "x" } });
  });

  it("account: name, password, sessions, factors", async () => {
    // A fresh product keeps this test independent of the first one.
    const fresh = await startProduct();
    const o = await createOwner(fresh);
    await addTotp(fresh, o);
    await check(o, "GET", "/api/v1/auth/me");
    await check(o, "PATCH", "/api/v1/auth/me", undefined, { name: "Olivia O." });
    await check(o, "POST", "/api/v1/auth/me/password", undefined, { currentPassword: "wrong", newPassword: "a new long password" });
    await check(o, "POST", "/api/v1/auth/me/password", undefined, { currentPassword: PASSWORD, newPassword: "a new long password" });
    const sessions = (await check(o, "GET", "/api/v1/auth/me/sessions")).body as { sessions: Array<{ id: string }> };
    await check(o, "DELETE", "/api/v1/auth/me/sessions/{id}", "/api/v1/auth/me/sessions/none");
    await check(o, "POST", "/api/v1/auth/me/totp");

    const key = new SoftPasskey(fresh.origin);
    const options = (await check(o, "POST", "/api/v1/auth/me/passkeys/options")).body as { challenge: string; rp: { id: string } };
    const added = await check(o, "POST", "/api/v1/auth/me/passkeys", undefined, { response: key.register(options), name: "Laptop" });
    expect(added.status).toBe(201);
    const anon = fresh.browser();
    const login = (await check(anon, "POST", "/api/v1/auth/login/passkey/options")).body as { challenge: string; rpId: string };
    expect((await check(anon, "POST", "/api/v1/auth/login/passkey", undefined, { response: key.authenticate(login) })).status).toBe(200);
    await check(o, "DELETE", "/api/v1/auth/me/passkeys/{id}", `/api/v1/auth/me/passkeys/${(added.body as { passkey: { id: string } }).passkey.id}`);
    await check(o, "DELETE", "/api/v1/auth/me/totp");
    await check(o, "DELETE", "/api/v1/auth/me/totp");
    await check(o, "DELETE", "/api/v1/auth/me/sessions/{id}", `/api/v1/auth/me/sessions/${sessions.sessions[0]!.id}`);
    await fresh.close();
  });

  it("members, links and tokens", async () => {
    const fresh = await startProduct();
    const o = await createOwner(fresh);
    await addTotp(fresh, o);
    const invited = (await check(o, "POST", "/api/v1/auth/members", undefined, { email: "ed@example.com", role: "editor" })).body as { member: { id: string }; link: string };
    await check(o, "POST", "/api/v1/auth/members", undefined, { email: "ed@example.com", role: "editor" });
    await check(o, "GET", "/api/v1/auth/members");
    const token = new URL(invited.link).searchParams.get("link")!;
    const ed = fresh.browser();
    await check(ed, "GET", "/api/v1/auth/links/{token}", `/api/v1/auth/links/${token}`);
    await check(ed, "POST", "/api/v1/auth/links/{token}", `/api/v1/auth/links/${token}`, { password: "short" });
    expect((await check(ed, "POST", "/api/v1/auth/links/{token}", `/api/v1/auth/links/${token}`, { password: PASSWORD })).status).toBe(200);
    await check(ed, "GET", "/api/v1/auth/links/{token}", `/api/v1/auth/links/${token}`);
    await check(ed, "GET", "/api/v1/auth/members");

    const id = invited.member.id;
    await check(o, "PATCH", "/api/v1/auth/members/{id}", `/api/v1/auth/members/${id}`, { role: "viewer" });
    await check(o, "PATCH", "/api/v1/auth/members/{id}", `/api/v1/auth/members/${id}`, { role: "god" });
    await check(o, "POST", "/api/v1/auth/members/{id}/reset", `/api/v1/auth/members/${id}/reset`, { mfa: true });
    await check(o, "POST", "/api/v1/auth/members/{id}/reset", "/api/v1/auth/members/none/reset", {});

    const created = (await check(o, "POST", "/api/v1/auth/tokens", undefined, { name: "CI", role: "editor", expiresInDays: 30 })).body as { id: string; token: string };
    await check(o, "POST", "/api/v1/auth/tokens", undefined, { name: "CI", role: "owner" });
    await check(o, "GET", "/api/v1/auth/tokens");
    const viaToken = fresh.browser();
    await check(viaToken, "GET", "/api/v1/auth/tokens", undefined, undefined, { authorization: `Bearer ${created.token}` });
    await check(o, "DELETE", "/api/v1/auth/tokens/{id}", `/api/v1/auth/tokens/${created.id}`);
    await check(o, "DELETE", "/api/v1/auth/tokens/{id}", `/api/v1/auth/tokens/${created.id}`);
    await check(o, "DELETE", "/api/v1/auth/members/{id}", `/api/v1/auth/members/${id}`);
    await check(o, "DELETE", "/api/v1/auth/members/{id}", `/api/v1/auth/members/${id}`);
    await fresh.close();
  });

  it("identity providers", async () => {
    const fresh = await startProduct({ allowInsecureIssuers: true });
    const o = await createOwner(fresh);
    await addTotp(fresh, o);
    const body = { preset: "keycloak", issuer: idp.issuer, clientId: "c", clientSecret: "s", roleMapping: { ops: "admin" } };
    await check(o, "POST", "/api/v1/auth/providers/discover", undefined, { issuer: idp.issuer });
    await check(o, "POST", "/api/v1/auth/providers/discover", undefined, { issuer: "ftp://x" });
    await check(o, "POST", "/api/v1/auth/providers", undefined, body);
    await check(o, "POST", "/api/v1/auth/providers", undefined, body);
    await check(o, "POST", "/api/v1/auth/providers", undefined, { ...body, preset: "nope" });
    await check(o, "GET", "/api/v1/auth/providers");
    await check(fresh.browser(), "GET", "/api/v1/auth/providers");
    await check(o, "PATCH", "/api/v1/auth/providers/{id}", "/api/v1/auth/providers/keycloak", { groupsClaim: "realm_access.roles", defaultRole: null });
    await check(o, "PATCH", "/api/v1/auth/providers/{id}", "/api/v1/auth/providers/keycloak", { scopes: ["email"] });
    await check(o, "PATCH", "/api/v1/auth/providers/{id}", "/api/v1/auth/providers/nope", {});
    await check(o, "DELETE", "/api/v1/auth/providers/{id}", "/api/v1/auth/providers/keycloak");
    await check(o, "DELETE", "/api/v1/auth/providers/{id}", "/api/v1/auth/providers/keycloak");
    await fresh.close();
  });

  it("OIDC redirects", async () => {
    const b = app.browser();
    await check(b, "GET", "/api/v1/auth/oidc/{id}/start", "/api/v1/auth/oidc/nope/start");
    await check(b, "GET", "/api/v1/auth/oidc/{id}/start", "/api/v1/auth/oidc/corp/start?setup=wrong");
    const ssoOnly = await startProduct({ passwords: false, oidc: [{ id: "corp", name: "Corp", issuer: idp.issuer, clientId: "c", allowInsecure: true }] });
    const setup = new URL(ssoOnly.auth.setupLink()!).searchParams.get("setup");
    await check(ssoOnly.browser(), "POST", "/api/v1/auth/setup", undefined, { token: setup, name: "O", email: "o@example.com", password: PASSWORD });
    await ssoOnly.close();
    const start = await check(b, "GET", "/api/v1/auth/oidc/{id}/start", "/api/v1/auth/oidc/corp/start");
    idp.next = { sub: "x", email: "x@example.com", email_verified: true };
    const atIdp = await fetch(start.headers.get("location")!, { redirect: "manual" });
    const back = new URL(atIdp.headers.get("location")!);
    expect((await check(b, "GET", "/api/v1/auth/oidc/{id}/callback", back.pathname + back.search)).status).toBe(302);
  });

  it("covers every operation", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
