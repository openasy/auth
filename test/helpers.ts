import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { encodeCBOR } from "@levischuck/tiny-cbor";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createAuth, type AuthEvent, type AuthOptions } from "../src/index.ts";
import { fromBase32, TOTP_STEP, totp } from "../src/crypto.ts";

export const PASSWORD = "correct horse battery staple";

/** The product: auth routes plus one route per role, like a product's own API. */
/** `port` 0 picks a free one; a fixed one is for providers that only send people back to a registered address. */
export async function startProduct(opts: Partial<AuthOptions> = {}, port = 0) {
  const db = new DatabaseSync(":memory:");
  const clock = { t: Date.parse("2026-10-20T10:00:00Z") };
  const events: AuthEvent[] = [];
  let origin = "http://localhost";
  const server: Server = createServer(async (req, res) => {
    if (await auth.handle(req, res)) return;
    const role = /^\/api\/v1\/needs\/(viewer|editor|admin|owner)$/.exec(req.url ?? "")?.[1] as "viewer" | undefined;
    if (!role) return res.writeHead(404).end();
    try {
      const p = auth.authorize(req, role);
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ kind: p.kind, role: p.role }));
    } catch (err) {
      const e = err as { status: number; code: string };
      res.writeHead(e.status, { "content-type": "application/json" }).end(JSON.stringify({ code: e.code }));
    }
  });
  await new Promise<void>((resolve) => server.listen(port, resolve));
  origin = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "test", productName: "OpenAsy Test", origin, now: () => clock.t, onEvent: (e) => events.push(e), ...opts });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, auth, origin, clock, events, close, browser: () => new Browser(origin) };
}

/** fetch with a cookie jar and the Origin header a browser sends. */
export class Browser {
  readonly cookies = new Map<string, string>();
  readonly origin: string;
  constructor(origin: string) {
    this.origin = origin;
  }
  async fetch(path: string, init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
    const res = await fetch(this.origin + path, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      redirect: "manual",
      headers: {
        origin: this.origin,
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(init.body !== undefined && { "content-type": "application/json" }),
        ...init.headers,
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(";");
      const [name, value] = [pair!.slice(0, pair!.indexOf("=")), pair!.slice(pair!.indexOf("=") + 1)];
      if (attrs.some((a) => a.trim() === "Max-Age=0")) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }
  async json<T = Record<string, unknown>>(path: string, init: Parameters<Browser["fetch"]>[1] = {}) {
    const res = await this.fetch(path, init);
    return { status: res.status, body: (res.status === 204 ? {} : await res.json()) as T };
  }
}

export async function createOwner(app: Awaited<ReturnType<typeof startProduct>>, b = app.browser()) {
  const token = new URL(app.auth.setupLink()!).searchParams.get("setup")!;
  const r = await b.json("/api/v1/auth/setup", { body: { token, name: "Olivia Owner", email: "owner@example.com", password: PASSWORD } });
  if (r.status !== 200) throw new Error(JSON.stringify(r.body));
  return b;
}

export const codeAt = (secret: string, ms: number) => totp(fromBase32(secret), Math.floor(ms / 1000 / TOTP_STEP));

/** Adds an authenticator app for the signed-in browser and returns its secret and recovery codes. */
export async function addTotp(app: Awaited<ReturnType<typeof startProduct>>, b: Browser) {
  const { body } = await b.json<{ secret: string }>("/api/v1/auth/me/totp", { body: {} });
  const r = await b.json<{ recoveryCodes: string[] }>("/api/v1/auth/me/totp/confirm", { body: { code: codeAt(body.secret, app.clock.t) } });
  if (r.status !== 200) throw new Error(JSON.stringify(r.body));
  // The confirmation used this step; later sign-ins need the next one.
  app.clock.t += TOTP_STEP * 1000;
  return { secret: body.secret, recoveryCodes: r.body.recoveryCodes };
}

export async function invite(app: Awaited<ReturnType<typeof startProduct>>, admin: Browser, email: string, role: string) {
  const r = await admin.json<{ member: { id: string }; link: string }>("/api/v1/auth/members", { body: { email, role } });
  if (r.status !== 201) throw new Error(JSON.stringify(r.body));
  const b = app.browser();
  const token = new URL(r.body.link).searchParams.get("link")!;
  const accepted = await b.json("/api/v1/auth/links/" + token, { body: { password: PASSWORD } });
  if (accepted.status !== 200) throw new Error(JSON.stringify(accepted.body));
  return { id: r.body.member.id, browser: b };
}

const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");

/** A software passkey (ES256, "none" attestation), as a phone or security key would answer. */
export class SoftPasskey {
  readonly id = randomBytes(16);
  private readonly keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  private counter = 0;
  userVerified = true;
  readonly origin: string;
  constructor(origin: string) {
    this.origin = origin;
  }

  private authData(rpId: string, attested: boolean) {
    const flags = 0x01 | (this.userVerified ? 0x04 : 0) | (attested ? 0x40 : 0);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(++this.counter);
    const parts = [createHash("sha256").update(rpId).digest(), Buffer.from([flags]), counter];
    if (attested) {
      const jwk = this.keys.publicKey.export({ format: "jwk" });
      const cose = new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x!, "base64url")],
        [-3, Buffer.from(jwk.y!, "base64url")],
      ]);
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.id.length);
      parts.push(Buffer.alloc(16), len, this.id, Buffer.from(encodeCBOR(cose)));
    }
    return Buffer.concat(parts);
  }

  private clientData(type: string, challenge: string) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }

  register(options: { challenge: string; rp: { id: string } }) {
    const attestationObject = encodeCBOR(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", this.authData(options.rp.id, true)]]) as never);
    return {
      id: b64u(this.id),
      rawId: b64u(this.id),
      type: "public-key",
      clientExtensionResults: {},
      response: { clientDataJSON: b64u(this.clientData("webauthn.create", options.challenge)), attestationObject: b64u(attestationObject), transports: ["internal"] },
    };
  }

  authenticate(options: { challenge: string; rpId: string }) {
    const authData = this.authData(options.rpId, false);
    const clientDataJSON = this.clientData("webauthn.get", options.challenge);
    const signature = createSign("sha256").update(Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()])).sign(this.keys.privateKey);
    return {
      id: b64u(this.id),
      rawId: b64u(this.id),
      type: "public-key",
      clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature) },
    };
  }
}

/** A minimal OIDC provider: discovery, JWKS, an authorize endpoint that signs in `next` at once, and a token endpoint. */
export async function startIdp() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const codes = new Map<string, { nonce: string; challenge: string; claims: Record<string, unknown>; clientId: string }>();
  const idp = {
    issuer: "",
    next: {} as Record<string, unknown>,
    /** Claims the userinfo endpoint answers with; unset, the provider has no userinfo endpoint. */
    userinfo: undefined as undefined | Record<string, unknown>,
    /** Set to make the ID token wrong in one way. */
    tamper: undefined as undefined | "audience" | "nonce",
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, idp.issuer);
    const json = (data: unknown) => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(data));
    if (url.pathname === "/.well-known/openid-configuration") {
      return json({
        issuer: idp.issuer,
        authorization_endpoint: `${idp.issuer}/authorize`,
        token_endpoint: `${idp.issuer}/token`,
        jwks_uri: `${idp.issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        ...(idp.userinfo && { userinfo_endpoint: `${idp.issuer}/userinfo` }),
      });
    }
    if (url.pathname === "/jwks") return json({ keys: [jwk] });
    if (url.pathname === "/userinfo" && idp.userinfo) {
      if (req.headers.authorization !== "Bearer at") return res.writeHead(401).end();
      return json(idp.userinfo);
    }
    if (url.pathname === "/authorize") {
      const code = randomBytes(8).toString("hex");
      const q = url.searchParams;
      if (q.get("code_challenge_method") !== "S256") return res.writeHead(400).end();
      codes.set(code, { nonce: q.get("nonce")!, challenge: q.get("code_challenge")!, claims: idp.next, clientId: q.get("client_id")! });
      const back = new URL(q.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", q.get("state")!);
      back.searchParams.set("iss", idp.issuer);
      return res.writeHead(302, { location: back.href }).end();
    }
    if (url.pathname === "/token") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const c = codes.get(form.get("code")!);
      codes.delete(form.get("code")!);
      const verifier = form.get("code_verifier") ?? "";
      if (!c || createHash("sha256").update(verifier).digest("base64url") !== c.challenge) {
        return res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid_grant" }));
      }
      const idToken = await new SignJWT({ ...c.claims, nonce: idp.tamper === "nonce" ? "other" : c.nonce })
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(idp.issuer)
        .setAudience(idp.tamper === "audience" ? "someone-else" : c.clientId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      return json({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: idToken });
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  idp.issuer = `http://localhost:${(server.address() as AddressInfo).port}`;
  return idp;
}

/** Follows the OIDC redirects like a browser: product → IdP → product callback. Returns the final redirect. */
export async function oidcSignIn(b: Browser, providerId: string, returnTo = "/") {
  const start = await b.fetch(`/api/v1/auth/oidc/${providerId}/start?return=${encodeURIComponent(returnTo)}`);
  const atIdp = await fetch(start.headers.get("location")!, { redirect: "manual" });
  const callback = new URL(atIdp.headers.get("location")!);
  const done = await b.fetch(callback.pathname + callback.search);
  return { status: done.status, location: done.headers.get("location")! };
}
