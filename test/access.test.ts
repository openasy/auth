import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAuth, grantFor, parseAccess, type AuthEvent } from "../src/index.ts";
import { addTotp, oidcSignIn, PASSWORD, startIdp, startProduct, type Browser } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "openasy-access-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
/** A new access file with these rules, and a function that replaces them. */
function accessFile(text: string) {
  const path = join(dir, `access-${++n}.yaml`);
  writeFileSync(path, text);
  return { path, write: (t: string) => writeFileSync(path, t) };
}

const OWNER = `access:
  - person: owner@example.com
    products: "*"
    role: owner
`;

describe("parseAccess", () => {
  it("reads rules by group and by person", () => {
    const rules = parseAccess(`${OWNER}  - group: ops\n    products: [test, logs]\n    role: editor\n`, "test");
    expect(rules).toEqual([
      { n: 1, group: null, person: "owner@example.com", products: "*", role: "owner" },
      { n: 2, group: "ops", person: null, products: ["test", "logs"], role: "editor" },
    ]);
  });

  it.each([
    ["not: a list", /access: list/],
    ["access: []\nextra: 1", /Unknown top-level field: extra/],
    ["access:\n  - group: ops\n    person: a@b.c\n    products: '*'\n    role: owner", /Rule 1: give either group or person/],
    ["access:\n  - group: ops\n    products: '*'\n    role: god", /Rule 1: role must be/],
    ["access:\n  - group: ops\n    products: [Infra]\n    role: owner", /Rule 1: products must be/],
    ["access:\n  - group: ops\n    products: '*'\n    role: owner\n    roles: x", /Rule 1: unknown field roles/],
    ["access:\n  - group: ops\n    products: '*'\n    role: owner\n    where: { env: prod }", /where is not supported yet/],
    ["access:\n  - group: ops\n    products: [logs]\n    role: owner", /No rule makes anyone an owner of test/],
    ["access: [", /Not YAML/],
  ])("refuses %j", (text, error) => {
    expect(() => parseAccess(text, "test")).toThrow(error);
  });
});

describe("grantFor", () => {
  const rules = parseAccess(
    `${OWNER}  - group: ops\n    products: [test]\n    role: viewer\n  - group: leads\n    products: "*"\n    role: admin\n  - group: everyone\n    products: "*"\n    role: user\n`,
    "test",
  );
  it("gives the highest role any rule gives, and says which rule", () => {
    expect(grantFor(rules, "test", "ann@example.com", ["ops", "leads"])).toEqual({ role: "admin", rule: "rule 3: group leads" });
    expect(grantFor(rules, "test", "OWNER@example.com", [])).toEqual({ role: "owner", rule: "rule 1: person owner@example.com" });
    expect(grantFor(rules, "logs", "ann@example.com", ["ops"])).toBeUndefined();
  });
  it("counts the user role only where the product has users", () => {
    expect(grantFor(rules, "test", "ann@example.com", ["everyone"])).toBeUndefined();
    expect(grantFor(rules, "test", "ann@example.com", ["everyone"], true)).toEqual({ role: "user", rule: "rule 4: group everyone" });
  });
});

describe("roles from the access file", () => {
  let idp: Awaited<ReturnType<typeof startIdp>>;
  let app: Awaited<ReturnType<typeof startProduct>>;
  let file: ReturnType<typeof accessFile>;
  const needs = (b: Browser, role: string) => b.fetch(`/api/v1/needs/${role}`);
  const member = (email: string) =>
    app.db.prepare("SELECT role, status, access_rule FROM auth_users WHERE email = ?").get(email) as {
      role: string;
      status: string;
      access_rule: string | null;
    };

  beforeEach(async () => {
    idp = await startIdp();
    file = accessFile(`${OWNER}  - group: ops\n    products: [test]\n    role: editor\n  - group: leads\n    products: "*"\n    role: admin\n`);
    app = await startProduct({
      access: file.path,
      oidc: [{ id: "corp", name: "Corp", issuer: idp.issuer, clientId: "c", clientSecret: "s", allowInsecure: true, scopes: ["openid", "email", "groups"] }],
    });
  });
  afterEach(async () => {
    app.auth.access?.stop();
    await app.close();
    await idp.close();
  });

  async function signIn(email: string, groups: string[]) {
    idp.next = { sub: email, email, email_verified: true, groups };
    const b = app.browser();
    return { b, r: await oidcSignIn(b, "corp") };
  }

  it("gives the role the file gives, and refuses people it names nowhere", async () => {
    const { b } = await signIn("ann@example.com", ["ops"]);
    expect((await needs(b, "editor")).status).toBe(200);
    expect((await needs(b, "admin")).status).toBe(403);
    expect(member("ann@example.com")).toEqual({ role: "editor", status: "active", access_rule: "rule 2: group ops" });
    const stranger = await signIn("eve@example.com", ["staff"]);
    expect(decodeURIComponent(stranger.r.location)).toMatch(/add you to the access file/);
  });

  it("follows a change to the file without a new sign-in, and ends the sessions of people it leaves out", async () => {
    const { b } = await signIn("ann@example.com", ["ops"]);
    file.write(`${OWNER}  - group: ops\n    products: [test]\n    role: viewer\n`);
    app.auth.access!.read();
    expect((await needs(b, "editor")).status).toBe(403);
    expect((await needs(b, "viewer")).status).toBe(200);
    expect(app.events).toContainEqual(expect.objectContaining({ type: "member-updated", method: "access-file", detail: "role editor -> viewer" }));

    file.write(OWNER);
    app.auth.access!.read();
    expect((await needs(b, "viewer")).status).toBe(401);
    expect(member("ann@example.com")).toMatchObject({ status: "disabled", access_rule: null });
    expect(decodeURIComponent((await signIn("ann@example.com", ["ops"])).r.location)).toMatch(/add you to the access file/);

    // Given access again, they are let in again.
    file.write(`${OWNER}  - group: ops\n    products: [test]\n    role: viewer\n`);
    app.auth.access!.read();
    expect(member("ann@example.com")).toMatchObject({ role: "viewer", status: "active" });
    expect((await needs((await signIn("ann@example.com", ["ops"])).b, "viewer")).status).toBe(200);
  });

  it("keeps the last good version of a file with a mistake, and says why", async () => {
    const { b } = await signIn("ann@example.com", ["ops"]);
    file.write("access:\n  - group: ops\n    role: admin\n");
    app.auth.access!.read();
    expect(app.auth.access!.state()).toMatchObject({
      path: file.path,
      rules: 3,
      error: 'Rule 1: products must be "*" or a list of product ids, such as [infra, logs].',
    });
    expect(app.events.at(-1)).toMatchObject({ type: "access-refused" });
    expect((await needs(b, "editor")).status).toBe(200);
  });

  it("leaves people whose groups are not known yet as they are", async () => {
    await signIn("ann@example.com", ["ops"]);
    // As after an upgrade: they signed in through the provider before groups were kept.
    app.db.prepare("UPDATE auth_users SET groups_at = NULL WHERE email = ?").run("ann@example.com");
    file.write(OWNER);
    app.auth.access!.read();
    expect(member("ann@example.com")).toMatchObject({ role: "editor", status: "active" });
  });

  it("refuses to invite, to change roles and to map a provider's groups", async () => {
    await signIn("lee@example.com", ["leads"]);
    const { b } = await signIn("owner@example.com", []);
    expect((await b.json("/api/v1/auth/members", { body: { email: "x@example.com", role: "viewer" } })).status).toBe(409);
    const lee = (app.db.prepare("SELECT id FROM auth_users WHERE email = ?").get("lee@example.com") as { id: string }).id;
    expect((await b.json(`/api/v1/auth/members/${lee}`, { method: "PATCH", body: { role: "viewer" } })).status).toBe(409);
    // Disabling someone at once still works.
    expect((await b.json(`/api/v1/auth/members/${lee}`, { method: "PATCH", body: { status: "disabled" } })).status).toBe(200);
    const add = await b.json("/api/v1/auth/providers", {
      body: { preset: "keycloak", name: "KC", issuer: "https://kc.example.com/realms/x", clientId: "c", roleMapping: { ops: "admin" } },
    });
    expect(add.status).toBe(409);
    const access = await b.json<{ file: { path: string; rules: number; error: null } }>("/api/v1/auth/access");
    expect(access.body.file).toMatchObject({ path: file.path, rules: 3, error: null });
    const members = await b.json<{ members: Array<{ email: string; accessRule: string }> }>("/api/v1/auth/members");
    expect(members.body.members).toContainEqual(expect.objectContaining({ email: "lee@example.com", accessRule: "rule 3: group leads" }));
  });

  it("revokes a token that has more than its creator has now", async () => {
    const { b } = await signIn("lee@example.com", ["leads"]);
    const t = await b.json<{ token: string }>("/api/v1/auth/tokens", { body: { name: "CI", role: "admin" } });
    expect(t.status).toBe(201);
    file.write(`${OWNER}  - group: leads\n    products: "*"\n    role: editor\n`);
    app.auth.access!.read();
    expect((await app.browser().fetch("/api/v1/needs/viewer", { headers: { authorization: `Bearer ${t.body.token}` } })).status).toBe(401);
  });

  it("sets up only someone the file gives a role, with that role", async () => {
    const setup = () => new URL(app.auth.setupLink()!).searchParams.get("setup");
    const refused = await app.browser().json("/api/v1/auth/setup", { body: { token: setup(), name: "Eve", email: "eve@example.com", password: PASSWORD } });
    expect(refused.status).toBe(409);
    const owner = app.browser();
    const ok = await owner.json("/api/v1/auth/setup", { body: { token: setup(), name: "Olivia", email: "owner@example.com", password: PASSWORD } });
    expect(ok.status).toBe(200);
    await addTotp(app, owner);
    expect(member("owner@example.com")).toEqual({ role: "owner", status: "active", access_rule: "rule 1: person owner@example.com" });
  });
});

describe("the access file across a restart", () => {
  it("applies the last good version when the file is broken at start", () => {
    const db = new DatabaseSync(":memory:");
    const file = accessFile(OWNER);
    const events: AuthEvent[] = [];
    const start = () => createAuth({ db, product: "test", productName: "Test", origin: "http://localhost", access: file.path, onEvent: (e) => events.push(e) });
    start().access!.stop();
    file.write("access: [");
    const again = start().access!;
    again.stop();
    expect(again.state()).toMatchObject({ rules: 1, error: expect.stringMatching(/^Not YAML/) });
    expect(events.at(-1)).toMatchObject({ type: "access-refused", detail: expect.stringMatching(/last good version stays/) });
  });
});
