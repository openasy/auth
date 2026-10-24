import { randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import {
  base32,
  DUMMY_HASH,
  fromBase32,
  hashPassword,
  matchTotp,
  normalizeRecoveryCode,
  randomToken,
  recoveryCodes,
  sealer,
  sha256,
  verifyPassword,
} from "./crypto.ts";
import { migrate } from "./db.ts";
import { brandFromEnv, type BrandSettings } from "./env.ts";
import { AuthError, clientIp, cookie, email as readEmail, parseCookies, readJson, SECURITY_HEADERS, sendJson, sendProblem, str } from "./http.ts";
import { createOidc, validateProvider, type OidcClaims, type OidcProvider } from "./oidc.ts";
import { PRESETS, preset as findPreset } from "./presets.ts";
import { atLeast, highest, isRole, needsMfa, type Role } from "./roles.ts";

export { AuthError, sendProblem, type AuthProblem } from "./http.ts";
export { ROLES, atLeast, type Role } from "./roles.ts";
export type { OidcProvider } from "./oidc.ts";
export { PRESETS, preset, type ProviderPreset } from "./presets.ts";
export { brandFromEnv, identityOrigin, oidcFromEnv, readSecretsKey, type BrandSettings } from "./env.ts";
export { authOpenApi, mergeOpenApi } from "./openapi.ts";

export interface AuthOptions {
  /** The product's SQLite database. The auth tables are added to it with an `auth_` prefix. */
  db: DatabaseSync;
  /** Short product id, used in API token prefixes: `oa_vulns_...`. */
  product: string;
  /** Shown in authenticator apps and passkey prompts: "OpenAsy Vulnerabilities". */
  productName: string;
  /** The URL people open, without a trailing slash: https://vulns.example.com. Sets cookie, CSRF and passkey scope. */
  origin: string;
  /** Other origins allowed to send requests with the session cookie, such as the Vite dev server. */
  trustedOrigins?: string[];
  /**
   * Origins whose pages may read and change the signed-in person's name, theme and language here with the session
   * cookie (CORS): Identity names the applications people sign in to through it, so they show what was chosen here
   * (ADR 0033). Asked at each request, so an application added later is allowed at once.
   */
  preferenceOrigins?: () => Iterable<string>;
  /** Sign in with email and password. Default true; turn it off when everyone uses OIDC. */
  passwords?: boolean;
  /**
   * Members may have the user role: people who use what the product offers, such as Identity's applications, without
   * managing the product. Off by default; products whose members all manage them leave it off.
   */
  users?: boolean;
  /**
   * Passwords another directory keeps, such as Active Directory for people Identity reads from it (ADR 0034): their
   * password is checked there at sign-in, and they cannot set one here.
   */
  externalPasswords?: {
    /** The directory that keeps this person's password, by name, or undefined when this product does. */
    managedBy: (userId: string) => string | undefined;
    verify: (userId: string, password: string) => Promise<boolean>;
  };
  /** After someone signs in through an identity provider, with the groups it sent; Identity keeps them (ADR 0033). */
  onOidcSignIn?: (signIn: { userId: string; provider: string; groups: string[] }) => void;
  /** Providers from the environment. More can be added under Settings, Sign-in, and stored in the database. */
  oidc?: OidcProvider[];
  /** For tests and local providers only: providers added under Settings may use an http:// issuer. */
  allowInsecureIssuers?: boolean;
  /** 32 bytes that encrypt TOTP secrets at rest (ADR 0021). Without it they are stored in clear and a warning is due. */
  secretsKey?: Buffer;
  session?: {
    /** Signed out after this long without a request. Default 60. */
    idleMinutes?: number;
    /** Signed out after this long whatever happens. Default 12. */
    absoluteHours?: number;
  };
  /** Where links in invitations and the first-start message point. Defaults use query strings on the origin. */
  links?: { setup?: (token: string) => string; password?: (token: string) => string; signIn?: (error?: string) => string };
  /** Every sign-in, failure and change to people or tokens, for the audit log (ADR 0013). */
  onEvent?: (event: AuthEvent) => void;
  /** The install's brand (ADR 0053); read from OPENASY_ORGANIZATION, OPENASY_ACCENT, OPENASY_LOGO and OPENASY_FAVICON when not given. */
  brand?: BrandSettings;
  /** For tests. */
  now?: () => number;
}

export interface AuthEvent {
  type:
    | "setup"
    | "sign-in"
    | "sign-in-failed"
    | "sign-out"
    | "session-ended"
    | "password-changed"
    | "mfa-enabled"
    | "mfa-removed"
    | "member-invited"
    | "member-updated"
    | "member-removed"
    | "token-created"
    | "token-revoked"
    | "provider-added"
    | "provider-updated"
    | "provider-removed";
  /** Who did it, when known. */
  actor?: string;
  /** Whom it was done to, when that is someone else. */
  target?: string;
  method?: string;
  ip: string;
  detail?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  status: "invited" | "active" | "disabled";
  createdAt: string;
  lastSignInAt: string | null;
  mfa: { totp: boolean; passkeys: number };
  providers: string[];
}

/** The second factor a session was opened with, or added during it. A passkey alone is method "passkey" and factor "passkey". */
export type Factor = "totp" | "passkey" | "recovery-code";

export type Principal =
  | { kind: "session"; user: User; role: Role; sessionId: string; method: string; mfa: boolean; factor: Factor | null }
  | { kind: "token"; tokenId: string; name: string; role: Role };

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  status: User["status"];
  password_hash: string | null;
  created_at: string;
  last_sign_in_at: string | null;
  theme: "system" | "light" | "dark" | null;
  locale: string | null;
}

interface ProviderRow {
  id: string;
  preset: string;
  name: string;
  issuer: string;
  client_id: string;
  client_secret: string | null;
  scopes: string;
  groups_claim: string | null;
  role_mapping: string;
  default_role: Role | null;
  allowed_domains: string;
  enabled: number;
  auto_redirect: number;
  created_at: string;
  updated_at: string;
}

const PREFIX = "/api/v1/auth";

/**
 * What a session is bound to: the browser and operating system from the User-Agent, without version numbers, so a
 * browser update keeps the session but a cookie copied into another browser or machine type does not work there.
 */
const deviceOf = (req: IncomingMessage) =>
  sha256(
    (req.headers["user-agent"] ?? "")
      .toLowerCase()
      .replace(/[\d._]+/g, "")
      .replace(/\s+/g, " ")
      .trim(),
  );
const MIN_PASSWORD = 12;
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
}

export function createAuth(opts: AuthOptions) {
  const { db, product, productName } = opts;
  const origin = opts.origin.replace(/\/$/, "");
  const passwords = opts.passwords ?? true;
  const users = opts.users ?? false;
  /** A role this product accepts: user only where `users` is on. */
  const roleAllowed = (r: unknown): r is Role => isRole(r) && (r !== "user" || users);
  const roleList = users ? "owner, admin, editor, viewer or user" : "owner, admin, editor or viewer";
  const brand = opts.brand ?? brandFromEnv(process.env);
  // The logo's address names its content, so a browser may keep it for a year and fetches a new one when it changes.
  const pictureUrl = (name: "logo" | "favicon") => {
    const p = brand[name];
    return p ? `${PREFIX}/brand/${name}?v=${p.etag}` : null;
  };
  const envProviders = opts.oidc ?? [];
  envProviders.forEach(validateProvider);
  for (const p of envProviders) {
    if (![...Object.values(p.roleMapping ?? {}), p.defaultRole ?? "viewer"].every(roleAllowed))
      throw new Error(`OIDC provider "${p.id}": the user role needs users: true`);
  }
  if (new Set(envProviders.map((p) => p.id)).size !== envProviders.length) throw new Error("OIDC provider ids must be unique");
  const now = opts.now ?? Date.now;
  const iso = (ms = now()) => new Date(ms).toISOString();
  const idleMs = (opts.session?.idleMinutes ?? 60) * 60_000;
  const absoluteMs = (opts.session?.absoluteHours ?? 12) * 3_600_000;
  const secure = origin.startsWith("https://");
  const rpID = new URL(origin).hostname;
  const allowedOrigins = new Set([origin, ...(opts.trustedOrigins ?? [])]);
  const secrets = sealer(opts.secretsKey);
  const links = {
    setup: opts.links?.setup ?? ((t: string) => `${origin}/?setup=${t}`),
    password: opts.links?.password ?? ((t: string) => `${origin}/?link=${t}`),
    signIn: opts.links?.signIn ?? ((e?: string) => `${origin}/${e ? `?auth_error=${encodeURIComponent(e)}` : ""}`),
  };
  const oidc = createOidc((id) => `${origin}${PREFIX}/oidc/${id}/callback`);
  const emit = (e: AuthEvent) => opts.onEvent?.(e);

  // __Host- cookies are only sent to this exact host, over HTTPS, for every path.
  const C = secure
    ? { session: "__Host-openasy-session", mfa: "__Host-openasy-mfa", webauthn: "__Host-openasy-webauthn", oidc: "__Host-openasy-oidc" }
    : { session: "openasy-session", mfa: "openasy-mfa", webauthn: "openasy-webauthn", oidc: "openasy-oidc" };
  const setCookie = (name: string, value: string, maxAge: number) => cookie(name, value, { secure, maxAge });
  const clearCookie = (name: string) => cookie(name, "", { secure, maxAge: 0 });

  migrate(db);

  // ---- Data access ----------------------------------------------------------------------------------------------

  const userRow = (id: string) => db.prepare("SELECT * FROM auth_users WHERE id = ?").get(id) as UserRow | undefined;
  const userByEmail = (email: string) => db.prepare("SELECT * FROM auth_users WHERE email = ?").get(email) as UserRow | undefined;
  const userCount = () => (db.prepare("SELECT COUNT(*) AS n FROM auth_users").get() as { n: number }).n;
  const hasTotp = (userId: string) => !!db.prepare("SELECT 1 FROM auth_totp WHERE user_id = ? AND confirmed = 1").get(userId);
  const passkeyCount = (userId: string) => (db.prepare("SELECT COUNT(*) AS n FROM auth_passkeys WHERE user_id = ?").get(userId) as { n: number }).n;
  const hasMfa = (userId: string) => hasTotp(userId) || passkeyCount(userId) > 0;
  const activeOwnersExcept = (userId: string) =>
    (db.prepare("SELECT COUNT(*) AS n FROM auth_users WHERE role = 'owner' AND status = 'active' AND id != ?").get(userId) as { n: number }).n;

  function toUser(row: UserRow): User {
    const ids = db.prepare("SELECT provider FROM auth_identities WHERE user_id = ? ORDER BY provider").all(row.id) as Array<{ provider: string }>;
    return {
      id: row.id,
      email: row.email,
      name: row.name,
      role: row.role,
      status: row.status,
      createdAt: row.created_at,
      lastSignInAt: row.last_sign_in_at,
      mfa: { totp: hasTotp(row.id), passkeys: passkeyCount(row.id) },
      providers: ids.map((i) => i.provider),
    };
  }

  function insertUser(u: { email: string; name: string; role: Role; status: User["status"]; passwordHash?: string | null }): UserRow {
    const id = randomUUID();
    db.prepare("INSERT INTO auth_users (id, email, name, role, status, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      id,
      u.email,
      u.name,
      u.role,
      u.status,
      u.passwordHash ?? null,
      iso(),
    );
    return userRow(id)!;
  }

  function createChallenge(kind: string, userId: string | null, data: Record<string, unknown>, ttlMs: number): string {
    const token = randomToken();
    db.prepare("INSERT INTO auth_challenges (id_hash, kind, user_id, data, expires_at) VALUES (?, ?, ?, ?, ?)").run(
      sha256(token),
      kind,
      userId,
      JSON.stringify(data),
      iso(now() + ttlMs),
    );
    return token;
  }

  function readChallenge(token: string | undefined, kind: string) {
    if (!token) return undefined;
    const row = db.prepare("SELECT * FROM auth_challenges WHERE id_hash = ? AND kind = ?").get(sha256(token), kind) as
      { id_hash: string; user_id: string | null; data: string; expires_at: string } | undefined;
    if (!row) return undefined;
    if (row.expires_at <= iso()) {
      db.prepare("DELETE FROM auth_challenges WHERE id_hash = ?").run(row.id_hash);
      return undefined;
    }
    return { userId: row.user_id, data: JSON.parse(row.data) as Record<string, unknown>, idHash: row.id_hash };
  }

  const dropChallenge = (idHash: string) => db.prepare("DELETE FROM auth_challenges WHERE id_hash = ?").run(idHash);
  const updateChallenge = (idHash: string, data: Record<string, unknown>) =>
    db.prepare("UPDATE auth_challenges SET data = ? WHERE id_hash = ?").run(JSON.stringify(data), idHash);
  const revokeSessions = (userId: string, exceptId?: string) =>
    db.prepare("DELETE FROM auth_sessions WHERE user_id = ? AND id != ?").run(userId, exceptId ?? "");

  // ---- Throttling -----------------------------------------------------------------------------------------------

  // Failed sign-ins per address and per address+email, kept in memory: a restart forgets them, which is acceptable
  // for one process (ADR 0018) and slows guessing to a crawl anyway.
  const failures = new Map<string, number[]>();
  const WINDOW = 15 * 60_000;
  function throttle(keys: Array<[string, number]>) {
    const t = now();
    for (const [key, max] of keys) {
      const recent = (failures.get(key) ?? []).filter((at) => t - at < WINDOW);
      failures.set(key, recent);
      if (recent.length >= max) throw new AuthError(429, "rate-limited", "Too many failed attempts. Wait 15 minutes and try again.");
    }
  }
  function fail(keys: string[]) {
    for (const key of keys) failures.set(key, [...(failures.get(key) ?? []), now()]);
    if (failures.size > 10_000) failures.clear();
  }

  // ---- Sessions -------------------------------------------------------------------------------------------------

  function startSession(req: IncomingMessage, user: UserRow, method: string, mfa: boolean, factor: Factor | null = null): string {
    const token = randomToken();
    const t = now();
    db.prepare(
      "INSERT INTO auth_sessions (id_hash, id, user_id, method, mfa, factor, ip, user_agent, device, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(
      sha256(token),
      randomUUID(),
      user.id,
      method,
      mfa ? 1 : 0,
      factor,
      clientIp(req),
      (req.headers["user-agent"] ?? "").slice(0, 256),
      deviceOf(req),
      iso(t),
      iso(t),
      iso(t + absoluteMs),
    );
    db.prepare("UPDATE auth_users SET last_sign_in_at = ? WHERE id = ?").run(iso(t), user.id);
    emit({ type: "sign-in", actor: user.id, method, ip: clientIp(req) });
    return setCookie(C.session, token, Math.floor(absoluteMs / 1000));
  }

  function signedIn(
    res: ServerResponse,
    req: IncomingMessage,
    user: UserRow,
    method: string,
    mfa: boolean,
    extra: string[] = [],
    factor: Factor | null = null,
  ) {
    const set = startSession(req, user, method, mfa, factor);
    sendJson(res, 200, { status: "signed-in", user: toUser(user), mfaSetupRequired: mfaSetupRequired(user, method) }, { "set-cookie": [set, ...extra] });
  }

  /** The directory that keeps someone's password, when it is not this product. */
  const managedBy = (userId: string) => opts.externalPasswords?.managedBy(userId);
  function ownPassword(userId: string) {
    const by = managedBy(userId);
    if (by) throw new AuthError(409, "conflict", `This password is kept in ${by}: change it there.`);
  }

  /** Owners and admins who signed in with a password must add a second factor before anything else. */
  const mfaSetupRequired = (user: UserRow, method: string) => method === "password" && needsMfa(user.role) && !hasMfa(user.id);

  function session(req: IncomingMessage) {
    const token = parseCookies(req.headers.cookie)[C.session];
    if (!token) return undefined;
    const row = db
      .prepare(
        "SELECT s.id AS session_id, s.id_hash, s.method, s.mfa, s.factor, s.device, s.last_seen_at, s.expires_at, u.* FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id WHERE s.id_hash = ?",
      )
      .get(sha256(token)) as
      | (UserRow & {
          session_id: string;
          id_hash: string;
          method: string;
          mfa: number;
          factor: Factor | null;
          device: string;
          last_seen_at: string;
          expires_at: string;
        })
      | undefined;
    if (!row) return undefined;
    if (row.device && row.device !== deviceOf(req)) {
      // The cookie is being used from another browser or system than the one that signed in: end the session.
      db.prepare("DELETE FROM auth_sessions WHERE id_hash = ?").run(row.id_hash);
      emit({ type: "session-ended", actor: row.id, ip: clientIp(req), detail: "session cookie used from another device", method: row.method });
      return undefined;
    }
    const t = now();
    if (row.expires_at <= iso(t) || Date.parse(row.last_seen_at) + idleMs <= t || row.status !== "active") {
      db.prepare("DELETE FROM auth_sessions WHERE id_hash = ?").run(row.id_hash);
      return undefined;
    }
    if (t - Date.parse(row.last_seen_at) > 60_000) db.prepare("UPDATE auth_sessions SET last_seen_at = ? WHERE id_hash = ?").run(iso(t), row.id_hash);
    return { user: row as UserRow, sessionId: row.session_id, method: row.method, mfa: row.mfa === 1, factor: row.factor };
  }

  /** The origin of a request for the preferences from a page that may ask for them (`preferenceOrigins`). */
  function preferenceOrigin(req: IncomingMessage): string | undefined {
    const o = req.headers.origin;
    if (!o || !opts.preferenceOrigins || new URL(req.url ?? "/", "http://localhost").pathname !== `${PREFIX}/me/preferences`) return undefined;
    for (const allowed of opts.preferenceOrigins()) if (allowed === o) return o;
    return undefined;
  }

  /** Requests with the session cookie must come from the product's own pages, or ask for the preferences from one allowed to. */
  function checkOrigin(req: IncomingMessage) {
    if (SAFE.has(req.method ?? "GET")) return;
    const o = req.headers.origin;
    if (o ? allowedOrigins.has(o) || preferenceOrigin(req) : req.headers["sec-fetch-site"] === "same-origin") return;
    throw new AuthError(403, "cross-site", `Requests must come from ${origin}.`);
  }

  function tokenPrincipal(secret: string): Principal {
    const row = db.prepare("SELECT * FROM auth_tokens WHERE secret_hash = ?").get(sha256(secret)) as
      { id: string; name: string; role: Role; expires_at: string; last_used_at: string | null } | undefined;
    if (!row || row.expires_at <= iso()) throw new AuthError(401, "invalid-token", "The API token is unknown or expired.");
    if (!row.last_used_at || now() - Date.parse(row.last_used_at) > 60_000)
      db.prepare("UPDATE auth_tokens SET last_used_at = ? WHERE id = ?").run(iso(), row.id);
    return { kind: "token", tokenId: row.id, name: row.name, role: row.role };
  }

  /**
   * Who is calling: an API token (`Authorization: Bearer oa_...`) or the session cookie. Throws 401 or 403 when the
   * caller may not do something that needs `min`. Use `{ allowMfaSetup: true }` only for routes an owner or admin
   * needs while adding their second factor.
   */
  function authorize(req: IncomingMessage, min: Role, { allowMfaSetup = false } = {}): Principal {
    const header = req.headers.authorization;
    let p: Principal;
    if (header?.startsWith("Bearer ")) {
      const secret = header.slice(7);
      if (!secret.startsWith("oa_")) throw new AuthError(401, "invalid-token", "Send an API token created in Settings, or sign in.");
      p = tokenPrincipal(secret);
    } else {
      const s = session(req);
      if (!s) throw new AuthError(401, "unauthenticated", "Sign in to continue.");
      checkOrigin(req);
      if (!allowMfaSetup && mfaSetupRequired(s.user, s.method)) throw new AuthError(403, "mfa-setup-required", "Set up two-step verification to continue.");
      p = { kind: "session", user: toUser(s.user), role: s.user.role, sessionId: s.sessionId, method: s.method, mfa: s.mfa, factor: s.factor };
    }
    if (!atLeast(p.role, min)) throw new AuthError(403, "forbidden", `This needs the ${min} role or higher.`);
    return p;
  }

  function sessionPrincipal(req: IncomingMessage, min: Role, o?: { allowMfaSetup?: boolean }) {
    const p = authorize(req, min, o);
    if (p.kind !== "session") throw new AuthError(403, "forbidden", "Only a signed-in person can do this, not an API token.");
    return p;
  }

  /** Removing a factor or replacing recovery codes needs a session that was opened with a second factor. */
  function requireStrongSession(p: Extract<Principal, { kind: "session" }>) {
    if (p.method === "password" && !p.mfa && hasMfa(p.user.id)) throw new AuthError(403, "mfa-required", "Sign in again with your second factor to do this.");
  }

  // ---- Second factors -------------------------------------------------------------------------------------------

  function checkTotp(userId: string, code: string): boolean {
    const row = db.prepare("SELECT secret, last_step FROM auth_totp WHERE user_id = ? AND confirmed = 1").get(userId) as
      { secret: string; last_step: number } | undefined;
    if (!row) return false;
    const step = matchTotp(fromBase32(secrets.open(row.secret)), code, now());
    if (step === null || step <= row.last_step) return false;
    db.prepare("UPDATE auth_totp SET last_step = ? WHERE user_id = ?").run(step, userId);
    return true;
  }

  function redeemRecoveryCode(userId: string, code: string): boolean {
    const r = db
      .prepare("UPDATE auth_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL")
      .run(iso(), userId, sha256(normalizeRecoveryCode(code)));
    return r.changes === 1;
  }

  function newRecoveryCodes(userId: string): string[] {
    const codes = recoveryCodes();
    db.prepare("DELETE FROM auth_recovery_codes WHERE user_id = ?").run(userId);
    const insert = db.prepare("INSERT INTO auth_recovery_codes (user_id, code_hash) VALUES (?, ?)");
    for (const c of codes) insert.run(userId, sha256(normalizeRecoveryCode(c)));
    return codes;
  }

  /** After the first factor is added, the user gets recovery codes and the session counts as verified. */
  function factorAdded(p: Extract<Principal, { kind: "session" }>, req: IncomingMessage, method: Factor) {
    // Adding a factor proves it is at hand, so the session counts as opened with it.
    db.prepare("UPDATE auth_sessions SET mfa = 1, factor = ? WHERE id = ?").run(method, p.sessionId);
    emit({ type: "mfa-enabled", actor: p.user.id, method, ip: clientIp(req) });
    const left = (db.prepare("SELECT COUNT(*) AS n FROM auth_recovery_codes WHERE user_id = ? AND used_at IS NULL").get(p.user.id) as { n: number }).n;
    return left === 0 ? newRecoveryCodes(p.user.id) : undefined;
  }

  function factorRemoved(userId: string) {
    if (!hasMfa(userId)) db.prepare("DELETE FROM auth_recovery_codes WHERE user_id = ?").run(userId);
  }

  const passkeys = (userId: string) =>
    db.prepare("SELECT id, name, created_at, last_used_at, transports FROM auth_passkeys WHERE user_id = ? ORDER BY created_at").all(userId) as Array<{
      id: string;
      name: string;
      created_at: string;
      last_used_at: string | null;
      transports: string;
    }>;

  // ---- OIDC -----------------------------------------------------------------------------------------------------

  function oidcUser(p: OidcProvider, c: OidcClaims, ip: string): UserRow {
    const refuse = (why: string) => {
      emit({ type: "sign-in-failed", method: `oidc:${p.id}`, ip, detail: why });
      return new AuthError(403, "forbidden", why);
    };
    if (p.allowedDomains && !(c.email && c.emailVerified && p.allowedDomains.includes(c.email.split("@")[1]!))) {
      throw refuse(`Your ${p.name} account is not in an allowed domain.`);
    }
    // Without the groups, the mapping would give the wrong role: refuse and say how to fix it at the provider.
    if (p.roleMapping && c.groupsOverage)
      throw refuse(
        `${p.name} left your groups out of the token because there are too many. An admin can send only the groups assigned to ${productName}'s registration.`,
      );
    const mapped = p.roleMapping ? highest(c.groups.map((g) => p.roleMapping![g]).filter(roleAllowed)) : undefined;
    const identity = db.prepare("SELECT user_id FROM auth_identities WHERE provider = ? AND subject = ?").get(p.id, c.subject) as
      { user_id: string } | undefined;
    let user = identity ? userRow(identity.user_id) : undefined;
    // An existing person is linked only by an email the provider says it has verified.
    if (!user && c.email && c.emailVerified) user = userByEmail(c.email);
    if (!user) {
      const role = mapped ?? p.defaultRole;
      if (!role || !c.email) throw refuse(`You have no access to ${productName}. Ask an admin to invite you.`);
      user = insertUser({ email: c.email, name: c.name ?? c.email, role, status: "active" });
    } else {
      if (user.status === "disabled") throw refuse("Your account is disabled.");
      if (p.roleMapping) {
        const role = mapped ?? p.defaultRole;
        if (!role) throw refuse(`You are in none of the groups that give access to ${productName}.`);
        // The groups decide the role, except that the last owner is never demoted by the IdP.
        if (role !== user.role && !(user.role === "owner" && activeOwnersExcept(user.id) === 0)) {
          db.prepare("UPDATE auth_users SET role = ? WHERE id = ?").run(role, user.id);
          emit({ type: "member-updated", target: user.id, method: `oidc:${p.id}`, ip, detail: `role ${user.role} -> ${role} from groups` });
        }
      }
      if (user.status === "invited") db.prepare("UPDATE auth_users SET status = 'active' WHERE id = ?").run(user.id);
      // The provider keeps the person's name, so a change made there shows here at the next sign-in.
      const name = c.name?.trim().slice(0, 128);
      if (name && name !== user.name) {
        db.prepare("UPDATE auth_users SET name = ? WHERE id = ?").run(name, user.id);
        emit({ type: "member-updated", target: user.id, method: `oidc:${p.id}`, ip, detail: "name from the provider" });
      }
    }
    db.prepare(
      "INSERT INTO auth_identities (provider, subject, user_id, email, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (provider, subject) DO UPDATE SET email = excluded.email, last_used_at = excluded.last_used_at",
    ).run(p.id, c.subject, user.id, c.email ?? null, iso(), iso());
    return userRow(user.id)!;
  }

  // ---- Identity providers: from the environment, and added under Settings ----------------------------------------

  const providerRow = (id: string) => db.prepare("SELECT * FROM auth_providers WHERE id = ?").get(id) as ProviderRow | undefined;
  const providerRows = () => db.prepare("SELECT * FROM auth_providers ORDER BY name COLLATE NOCASE").all() as unknown as ProviderRow[];

  const fromRow = (r: ProviderRow): OidcProvider => ({
    id: r.id,
    name: r.name,
    issuer: r.issuer,
    clientId: r.client_id,
    clientSecret: r.client_secret ? secrets.open(r.client_secret) : undefined,
    scopes: JSON.parse(r.scopes) as string[],
    groupsClaim: r.groups_claim ?? undefined,
    roleMapping: Object.keys(JSON.parse(r.role_mapping) as object).length ? (JSON.parse(r.role_mapping) as Record<string, Role>) : undefined,
    defaultRole: r.default_role ?? undefined,
    allowedDomains: (JSON.parse(r.allowed_domains) as string[]).length ? (JSON.parse(r.allowed_domains) as string[]) : undefined,
    allowInsecure: opts.allowInsecureIssuers,
    autoRedirect: r.auto_redirect === 1 || undefined,
    preset: r.preset,
  });

  /** Every provider people can sign in with now: the environment's first, then the enabled ones from Settings. */
  const providers = (): OidcProvider[] => [
    ...envProviders,
    ...providerRows()
      .filter((r) => r.enabled)
      .map(fromRow),
  ];

  /**
   * Identity, when people sign in through it: it keeps their account, their role and their preferences (ADR 0033).
   * Only from the environment, as the product's content security policy lets its pages call Identity from start
   * (identityOrigin).
   */
  function identityOf(): { name: string; url: string } | null {
    const p = envProviders.find((x) => x.preset === "openasy-identity");
    return p ? { name: p.name, url: new URL(p.issuer).origin } : null;
  }

  const preferencesOf = (row: UserRow) => ({ name: row.name, theme: row.theme, locale: row.locale });

  /** The first person, through a provider and the one-time setup link: they become the owner (ADR 0013). */
  function oidcOwner(p: OidcProvider, c: OidcClaims, setupHash: string, ip: string): UserRow {
    const setup = db.prepare("SELECT expires_at FROM auth_challenges WHERE id_hash = ? AND kind = 'setup'").get(setupHash) as
      { expires_at: string } | undefined;
    if (!setup || setup.expires_at <= iso() || userCount() > 0)
      throw new AuthError(403, "invalid-token", "This setup link is used or expired. Restart the product for a new one.");
    if (!c.email) throw new AuthError(403, "forbidden", `${p.name} did not say your email address. Allow the email scope for ${productName}.`);
    if (p.allowedDomains && !(c.emailVerified && p.allowedDomains.includes(c.email.split("@")[1]!)))
      throw new AuthError(403, "forbidden", `Your ${p.name} account is not in an allowed domain.`);
    const user = insertUser({ email: c.email, name: c.name ?? c.email, role: "owner", status: "active" });
    dropChallenge(setupHash);
    db.prepare("INSERT INTO auth_identities (provider, subject, user_id, email, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)").run(
      p.id,
      c.subject,
      user.id,
      c.email,
      iso(),
      iso(),
    );
    emit({ type: "setup", actor: user.id, method: `oidc:${p.id}`, ip });
    return user;
  }

  const provider = (id: string) => {
    const p = providers().find((x) => x.id === id);
    if (!p) throw new AuthError(404, "not-found", `No sign-in provider "${id}".`);
    return p;
  };

  const redirectUri = (id: string) => `${origin}${PREFIX}/oidc/${id}/callback`;

  /** A provider as Settings shows it: never the client secret. */
  function providerView(p: OidcProvider, row?: ProviderRow) {
    return {
      id: p.id,
      name: p.name,
      preset: row?.preset ?? "generic",
      source: row ? "settings" : "environment",
      enabled: row ? row.enabled === 1 : true,
      issuer: p.issuer,
      clientId: p.clientId,
      hasClientSecret: row ? !!row.client_secret : !!p.clientSecret,
      scopes: p.scopes ?? ["openid", "email", "profile"],
      groupsClaim: p.groupsClaim ?? null,
      roleMapping: p.roleMapping ?? {},
      defaultRole: p.defaultRole ?? null,
      allowedDomains: p.allowedDomains ?? [],
      autoRedirect: !!p.autoRedirect,
      redirectUri: redirectUri(p.id),
      createdAt: row?.created_at ?? null,
      updatedAt: row?.updated_at ?? null,
    };
  }

  /** Reads and checks provider settings from a request; fields left out keep `current`. */
  function providerInput(b: Record<string, unknown>, current?: ProviderRow) {
    const bad = (m: string) => new AuthError(422, "invalid-body", m);
    const presetId = current?.preset ?? (b.preset === undefined ? "generic" : b.preset);
    const pr = typeof presetId === "string" ? findPreset(presetId) : undefined;
    if (!pr) throw bad(`preset must be one of ${PRESETS.map((x) => x.id).join(", ")}.`);
    const text = (name: string, max: number) => {
      const v = b[name];
      if (v === undefined) return undefined;
      if (typeof v !== "string" || !v.trim() || v.length > max) throw bad(`${name} must be text, at most ${max} characters.`);
      return v.trim();
    };
    const issuer = text("issuer", 512) ?? current?.issuer;
    if (!issuer) throw bad("issuer is required: the address in the provider's discovery document.");
    try {
      validateProvider({ id: "check", name: "", issuer, clientId: "", allowInsecure: opts.allowInsecureIssuers });
    } catch (err) {
      throw bad((err as Error).message.replace('for "check" ', ""));
    }
    const clientId = text("clientId", 256) ?? current?.client_id;
    if (!clientId) throw bad("clientId is required.");
    let clientSecret = current?.client_secret ?? null;
    if (b.clientSecret === null) clientSecret = null;
    else if (b.clientSecret !== undefined) clientSecret = secrets.seal(text("clientSecret", 1024)!);
    const list = (name: string, fallback: string[]) => {
      const v = b[name];
      if (v === undefined) return fallback;
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || !x.trim() || x.length > 256)) throw bad(`${name} must be a list of text.`);
      return (v as string[]).map((x) => x.trim());
    };
    const scopes = list("scopes", current ? (JSON.parse(current.scopes) as string[]) : pr.scopes);
    if (!scopes.includes("openid")) throw bad("scopes must include openid.");
    const allowedDomains = list("allowedDomains", current ? (JSON.parse(current.allowed_domains) as string[]) : []).map((d) => d.toLowerCase());
    let groupsClaim = current ? current.groups_claim : (pr.groupsClaim ?? null);
    if (b.groupsClaim === null) groupsClaim = null;
    else if (b.groupsClaim !== undefined) groupsClaim = text("groupsClaim", 256)!;
    let roleMapping = current ? (JSON.parse(current.role_mapping) as Record<string, Role>) : {};
    if (b.roleMapping !== undefined) {
      const m = b.roleMapping;
      if (!m || typeof m !== "object" || Array.isArray(m) || Object.entries(m).some(([g, r]) => !g.trim() || !roleAllowed(r))) {
        throw bad(`roleMapping must map group names to ${roleList}.`);
      }
      roleMapping = m as Record<string, Role>;
    }
    let defaultRole = current?.default_role ?? null;
    if (b.defaultRole === null) defaultRole = null;
    else if (b.defaultRole !== undefined) {
      if (!roleAllowed(b.defaultRole)) throw bad(`defaultRole must be ${roleList} or null.`);
      defaultRole = b.defaultRole;
    }
    if (b.enabled !== undefined && typeof b.enabled !== "boolean") throw bad("enabled must be true or false.");
    if (b.autoRedirect !== undefined && typeof b.autoRedirect !== "boolean") throw bad("autoRedirect must be true or false.");
    return {
      preset: pr.id,
      name: text("name", 64) ?? current?.name ?? pr.name,
      issuer,
      clientId,
      clientSecret,
      scopes,
      groupsClaim,
      roleMapping,
      defaultRole,
      allowedDomains,
      enabled: b.enabled === undefined ? (current ? current.enabled === 1 : true) : b.enabled,
      autoRedirect: b.autoRedirect === undefined ? current?.auto_redirect === 1 : b.autoRedirect,
    };
  }

  /** Only one provider may take the sign-in screen: two would leave it to chance which one people end up at. */
  function onlyAutoRedirect(id: string, autoRedirect: boolean) {
    if (!autoRedirect) return;
    const other = [...envProviders, ...providerRows().map(fromRow)].find((x) => x.autoRedirect && x.id !== id);
    if (other) throw new AuthError(409, "conflict", `The sign-in screen already goes straight to ${other.name}. Turn that off first.`);
  }

  /** People linked to a provider stop being linked when it is removed or points elsewhere: the next provider's subjects are not theirs. */
  const unlinkProvider = (id: string) => db.prepare("DELETE FROM auth_identities WHERE provider = ?").run(id);

  /** Only paths on this product, never another site. */
  const safeReturn = (v: string | null) => (v && v.startsWith("/") && !v.startsWith("//") && !v.startsWith("/\\") ? v : "/");

  // ---- Routes ---------------------------------------------------------------------------------------------------

  const ok = (res: ServerResponse, data?: unknown, headers?: Record<string, string | string[]>) => sendJson(res, data === undefined ? 204 : 200, data, headers);

  function newPassword(body: Record<string, unknown>, name = "password") {
    const pw = str(body, name, { min: MIN_PASSWORD, max: 256 });
    return pw;
  }

  function memberRole(body: Record<string, unknown>): Role {
    if (!roleAllowed(body.role)) throw new AuthError(422, "invalid-body", `role must be ${roleList}.`);
    return body.role;
  }

  /** Only owners manage owners; admins manage everyone else. */
  function mayManage(actor: Role, target: Role) {
    if (target === "owner" ? actor !== "owner" : !atLeast(actor, "admin")) throw new AuthError(403, "forbidden", "Only an owner can manage owners.");
  }

  function member(id: string) {
    const row = userRow(id);
    if (!row) throw new AuthError(404, "not-found", "No such member.");
    return row;
  }

  const routes: Array<{ method: string; path: string; handle: (ctx: Ctx) => unknown }> = [
    // What the sign-in screen should offer.
    {
      method: "GET",
      path: "/methods",
      handle: () => {
        const all = providers();
        const auto = all.filter((p) => p.autoRedirect);
        return {
          passwords,
          passkeys: true,
          users,
          providers: all.map((p) => ({ id: p.id, name: p.name })),
          autoRedirect: auto.length === 1 ? auto[0]!.id : null,
          setupRequired: userCount() === 0,
          brand: {
            organization: brand.organization ?? null,
            accent: brand.accent ?? null,
            logo: pictureUrl("logo"),
            favicon: pictureUrl("favicon"),
            support: brand.support ?? null,
          },
        };
      },
    },
    // The brand's logo and tab icon, from this product's own address, so the page never loads a picture from elsewhere
    // (ADR 0053).
    ...(["logo", "favicon"] as const).map((name): { method: string; path: string; handle: (ctx: Ctx) => unknown } => ({
      method: "GET",
      path: `/brand/${name}`,
      handle: ({ res }) => {
        const p = brand[name];
        if (!p) throw new AuthError(404, "not-found", `No ${name}: OPENASY_${name.toUpperCase()} is not set.`);
        res
          .writeHead(200, {
            ...SECURITY_HEADERS,
            "content-type": p.type,
            "content-length": p.body.length,
            "cache-control": "public, max-age=31536000, immutable",
            // An SVG may hold script: sandboxed, it never runs, even when the picture is opened on its own.
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            etag: `"${p.etag}"`,
          })
          .end(p.body);
      },
    })),

    // First start: the one-time link printed in the log creates the owner (ADR 0013).
    {
      method: "POST",
      path: "/setup",
      handle: async ({ req, res, body }) => {
        checkOrigin(req);
        const b = await body();
        const ch = readChallenge(str(b, "token", { max: 128 }), "setup");
        if (!ch || userCount() > 0) throw new AuthError(403, "invalid-token", "This setup link is used or expired. Restart the product for a new one.");
        // With password sign-in off, the owner signs in through a provider: a password nobody can use is no owner.
        if (!passwords && providers().length)
          throw new AuthError(409, "conflict", `Password sign-in is off: continue with ${providers()[0]!.name} to become the owner.`);
        const user = insertUser({
          email: readEmail(b),
          name: str(b, "name", { max: 128 }).trim(),
          role: "owner",
          status: "active",
          passwordHash: await hashPassword(newPassword(b)),
        });
        dropChallenge(ch.idHash);
        emit({ type: "setup", actor: user.id, ip: clientIp(req) });
        signedIn(res, req, user, "password", false);
      },
    },

    {
      method: "POST",
      path: "/login",
      handle: async ({ req, res, body }) => {
        checkOrigin(req);
        if (!passwords) throw new AuthError(404, "not-found", "Password sign-in is turned off.");
        const b = await body();
        const email = readEmail(b);
        const password = str(b, "password", { max: 256 });
        const ip = clientIp(req);
        throttle([
          [`ip:${ip}`, 50],
          [`ip:${ip}:${email}`, 10],
        ]);
        const user = userByEmail(email);
        // A password another directory keeps is checked there; the local hash is still computed, so the answer takes
        // as long either way.
        const external = user && managedBy(user.id);
        const localValid = await verifyPassword(password, (!external && user?.password_hash) || DUMMY_HASH);
        const valid = external ? await opts.externalPasswords!.verify(user!.id, password).catch(() => false) : localValid && !!user?.password_hash;
        if (!user || !valid || user.status !== "active") {
          fail([`ip:${ip}`, `ip:${ip}:${email}`]);
          emit({
            type: "sign-in-failed",
            actor: user?.id,
            method: "password",
            ip,
            detail: user && valid ? `account ${user.status}` : "wrong email or password",
          });
          throw new AuthError(401, "invalid-credentials", "Wrong email or password.");
        }
        if (hasMfa(user.id)) {
          const pending = createChallenge("mfa", user.id, { attempts: 0 }, 5 * 60_000);
          const methods = [...(hasTotp(user.id) ? ["totp"] : []), ...(passkeyCount(user.id) ? ["passkey"] : []), "recovery-code"];
          return ok(res, { status: "mfa-required", methods }, { "set-cookie": setCookie(C.mfa, pending, 300) });
        }
        signedIn(res, req, user, "password", false);
      },
    },

    // Second step after the password: a TOTP code or a recovery code. Passkeys use /login/passkey.
    {
      method: "POST",
      path: "/login/mfa",
      handle: async ({ req, res, body }) => {
        checkOrigin(req);
        const ch = readChallenge(parseCookies(req.headers.cookie)[C.mfa], "mfa");
        if (!ch?.userId) throw new AuthError(401, "unauthenticated", "Sign in with your password again.");
        const b = await body();
        const attempts = Number(ch.data.attempts) + 1;
        if (attempts > 5) {
          dropChallenge(ch.idHash);
          throw new AuthError(429, "rate-limited", "Too many wrong codes. Sign in with your password again.");
        }
        updateChallenge(ch.idHash, { attempts });
        const code = str(b, "code", { max: 32, optional: true });
        const recovery = str(b, "recoveryCode", { max: 32, optional: true });
        const valid = code ? checkTotp(ch.userId, code) : recovery ? redeemRecoveryCode(ch.userId, recovery) : false;
        if (!valid) {
          emit({ type: "sign-in-failed", actor: ch.userId, method: code ? "totp" : "recovery-code", ip: clientIp(req), detail: "wrong code" });
          throw new AuthError(401, "invalid-credentials", "That code is not valid.");
        }
        dropChallenge(ch.idHash);
        const user = userRow(ch.userId)!;
        if (user.status !== "active") throw new AuthError(401, "invalid-credentials", "Your account is disabled.");
        signedIn(res, req, user, "password", true, [clearCookie(C.mfa)], code ? "totp" : "recovery-code");
      },
    },

    // Passkeys: alone (the passkey is both factors when the device verified the person), or as the second step.
    {
      method: "POST",
      path: "/login/passkey/options",
      handle: async ({ req, res }) => {
        checkOrigin(req);
        const mfa = readChallenge(parseCookies(req.headers.cookie)[C.mfa], "mfa");
        const allow = mfa?.userId
          ? passkeys(mfa.userId).map((k) => ({ id: k.id, transports: JSON.parse(k.transports) as AuthenticatorTransport[] }))
          : undefined;
        const options = await generateAuthenticationOptions({ rpID, allowCredentials: allow, userVerification: mfa ? "preferred" : "required" });
        const id = createChallenge("webauthn-login", mfa?.userId ?? null, { challenge: options.challenge, mfa: mfa?.idHash ?? null }, 5 * 60_000);
        ok(res, options, { "set-cookie": setCookie(C.webauthn, id, 300) });
      },
    },
    {
      method: "POST",
      path: "/login/passkey",
      handle: async ({ req, res, body }) => {
        checkOrigin(req);
        const ch = readChallenge(parseCookies(req.headers.cookie)[C.webauthn], "webauthn-login");
        if (!ch) throw new AuthError(401, "unauthenticated", "The passkey request expired. Try again.");
        dropChallenge(ch.idHash);
        const response = (await body()).response as AuthenticationResponseJSON | undefined;
        if (!response || typeof response.id !== "string") throw new AuthError(422, "invalid-body", "response must be the passkey's answer.");
        const key = db.prepare("SELECT * FROM auth_passkeys WHERE id = ?").get(response.id) as
          { id: string; user_id: string; public_key: Uint8Array; counter: number; transports: string } | undefined;
        const ip = clientIp(req);
        const failed = () => {
          emit({ type: "sign-in-failed", actor: key?.user_id, method: "passkey", ip, detail: "passkey not accepted" });
          return new AuthError(401, "invalid-credentials", "This passkey is not registered here.");
        };
        if (!key || (ch.userId && key.user_id !== ch.userId)) throw failed();
        const verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: String(ch.data.challenge),
          expectedOrigin: [...allowedOrigins],
          expectedRPID: rpID,
          credential: {
            id: key.id,
            publicKey: new Uint8Array(key.public_key),
            counter: key.counter,
            transports: JSON.parse(key.transports) as AuthenticatorTransport[],
          },
          requireUserVerification: !ch.userId,
        }).catch(() => ({ verified: false as const, authenticationInfo: undefined }));
        if (!verification.verified || !verification.authenticationInfo) throw failed();
        db.prepare("UPDATE auth_passkeys SET counter = ?, last_used_at = ? WHERE id = ?").run(verification.authenticationInfo.newCounter, iso(), key.id);
        if (typeof ch.data.mfa === "string") dropChallenge(ch.data.mfa);
        const user = userRow(key.user_id)!;
        if (user.status !== "active") throw failed();
        signedIn(res, req, user, ch.userId ? "password" : "passkey", true, [clearCookie(C.webauthn), clearCookie(C.mfa)], "passkey");
      },
    },

    // OIDC: the browser is sent to the provider and comes back to /callback.
    {
      method: "GET",
      path: "/oidc/:id/start",
      handle: async ({ res, url, params }) => {
        const p = provider(params[0]!);
        // ?setup=<token>: the first person becomes the owner through this provider, with the one-time setup link.
        const setupToken = url.searchParams.get("setup") ?? undefined;
        const setup = setupToken ? readChallenge(setupToken, "setup") : undefined;
        if (setupToken && (!setup || userCount() > 0))
          throw new AuthError(403, "invalid-token", "This setup link is used or expired. Restart the product for a new one.");
        const s = await oidc.start(p);
        const id = createChallenge(
          "oidc",
          null,
          {
            provider: p.id,
            verifier: s.verifier,
            state: s.state,
            nonce: s.nonce,
            return: safeReturn(url.searchParams.get("return")),
            setup: setup?.idHash ?? null,
          },
          10 * 60_000,
        );
        res.writeHead(302, { location: s.url, "set-cookie": setCookie(C.oidc, id, 600), "cache-control": "no-store" }).end();
      },
    },
    {
      method: "GET",
      path: "/oidc/:id/callback",
      handle: async ({ req, res, url, params }) => {
        const redirect = (location: string, cookies: string[]) => res.writeHead(302, { location, "set-cookie": cookies, "cache-control": "no-store" }).end();
        const ch = readChallenge(parseCookies(req.headers.cookie)[C.oidc], "oidc");
        if (ch) dropChallenge(ch.idHash);
        try {
          const p = provider(params[0]!);
          // The state cookie ties the answer to the browser that started; without it anyone could log you in as them.
          if (!ch || ch.data.provider !== p.id)
            throw new AuthError(400, "invalid-body", "The sign-in took too long or was started in another browser. Try again.");
          if (url.searchParams.get("error"))
            throw new AuthError(401, "invalid-credentials", `${p.name}: ${url.searchParams.get("error_description") ?? url.searchParams.get("error")}`);
          const claims = await oidc
            .finish(p, new URL(`${origin}${url.pathname}${url.search}`), {
              verifier: String(ch.data.verifier),
              state: String(ch.data.state),
              nonce: String(ch.data.nonce),
            })
            .catch((err: Error) => {
              throw new AuthError(401, "invalid-credentials", `${p.name} sign-in could not be verified: ${err.message}`);
            });
          const user = ch.data.setup ? oidcOwner(p, claims, String(ch.data.setup), clientIp(req)) : oidcUser(p, claims, clientIp(req));
          opts.onOidcSignIn?.({ userId: user.id, provider: p.id, groups: claims.groups });
          redirect(String(ch.data.return), [startSession(req, user, `oidc:${p.id}`, false), clearCookie(C.oidc)]);
        } catch (err) {
          if (!(err instanceof AuthError)) throw err;
          redirect(links.signIn(err.message), [clearCookie(C.oidc)]);
        }
      },
    },

    {
      method: "POST",
      path: "/logout",
      handle: ({ req, res }) => {
        const s = session(req);
        if (s) {
          checkOrigin(req);
          db.prepare("DELETE FROM auth_sessions WHERE id = ?").run(s.sessionId);
          emit({ type: "sign-out", actor: s.user.id, ip: clientIp(req) });
        }
        ok(res, undefined, { "set-cookie": clearCookie(C.session) });
      },
    },

    // Invitations and password resets: a one-time link sets the password.
    {
      method: "GET",
      path: "/links/:token",
      handle: ({ params }) => {
        const ch = readChallenge(params[0], "invite") ?? readChallenge(params[0], "reset");
        if (!ch?.userId) throw new AuthError(404, "not-found", "This link is used or expired. Ask an admin for a new one.");
        const u = userRow(ch.userId)!;
        return { kind: ch.data.kind, email: u.email, name: u.name, productName };
      },
    },
    {
      method: "POST",
      path: "/links/:token",
      handle: async ({ req, res, params, body }) => {
        checkOrigin(req);
        const ch = readChallenge(params[0], "invite") ?? readChallenge(params[0], "reset");
        if (!ch?.userId) throw new AuthError(404, "not-found", "This link is used or expired. Ask an admin for a new one.");
        const b = await body();
        ownPassword(ch.userId);
        const hash = await hashPassword(newPassword(b));
        const u = userRow(ch.userId)!;
        if (u.status === "disabled") throw new AuthError(403, "forbidden", "Your account is disabled.");
        const name = str(b, "name", { max: 128, optional: true })?.trim() || u.name;
        db.prepare("UPDATE auth_users SET password_hash = ?, name = ?, status = 'active' WHERE id = ?").run(hash, name, u.id);
        dropChallenge(ch.idHash);
        revokeSessions(u.id);
        emit({ type: "password-changed", actor: u.id, ip: clientIp(req), detail: String(ch.data.kind) });
        signedIn(res, req, userRow(u.id)!, "password", false);
      },
    },

    // The signed-in person.
    {
      method: "GET",
      path: "/me",
      handle: ({ req }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const row = userRow(p.user.id)!;
        return {
          user: p.user,
          session: { id: p.sessionId, method: p.method, mfa: p.mfa, factor: p.factor },
          passwordManagedBy: opts.externalPasswords?.managedBy(p.user.id) ?? null,
          mfaSetupRequired: mfaSetupRequired(row, p.method),
          hasPassword: !!row.password_hash,
          passkeys: passkeys(p.user.id).map((k) => ({ id: k.id, name: k.name, createdAt: k.created_at, lastUsedAt: k.last_used_at })),
          recoveryCodesLeft: (db.prepare("SELECT COUNT(*) AS n FROM auth_recovery_codes WHERE user_id = ? AND used_at IS NULL").get(p.user.id) as { n: number })
            .n,
          managedBy: identityOf(),
          preferences: preferencesOf(row),
        };
      },
    },
    {
      method: "PATCH",
      path: "/me",
      handle: async ({ req, body }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const name = str(await body(), "name", { max: 128 }).trim();
        db.prepare("UPDATE auth_users SET name = ? WHERE id = ?").run(name, p.user.id);
        return toUser(userRow(p.user.id)!);
      },
    },
    // The person's name, theme and language. Identity's are read and changed by the applications that sign in
    // through it, from their own pages (preferenceOrigins), so a choice made in one shows in all of them.
    {
      method: "GET",
      path: "/me/preferences",
      handle: ({ req }) => preferencesOf(userRow(sessionPrincipal(req, "user", { allowMfaSetup: true }).user.id)!),
    },
    {
      method: "PATCH",
      path: "/me/preferences",
      handle: async ({ req, body }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const b = await body();
        const unknown = Object.keys(b).filter((k) => k !== "theme" && k !== "locale");
        if (unknown.length) throw new AuthError(422, "invalid-body", `Unknown field: ${unknown.join(", ")}. Send theme, locale or both.`);
        if (b.theme !== undefined) {
          if (b.theme !== "system" && b.theme !== "light" && b.theme !== "dark")
            throw new AuthError(422, "invalid-body", "theme must be system, light or dark.");
          db.prepare("UPDATE auth_users SET theme = ? WHERE id = ?").run(b.theme, p.user.id);
        }
        if (b.locale !== undefined) {
          if (typeof b.locale !== "string" || !/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(b.locale))
            throw new AuthError(422, "invalid-body", "locale must be a language tag such as en or tr.");
          db.prepare("UPDATE auth_users SET locale = ? WHERE id = ?").run(b.locale, p.user.id);
        }
        return preferencesOf(userRow(p.user.id)!);
      },
    },
    {
      method: "POST",
      path: "/me/password",
      handle: async ({ req, res, body }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const b = await body();
        ownPassword(p.user.id);
        const row = userRow(p.user.id)!;
        if (row.password_hash && !(await verifyPassword(str(b, "currentPassword", { max: 256 }), row.password_hash))) {
          throw new AuthError(401, "invalid-credentials", "The current password is wrong.");
        }
        db.prepare("UPDATE auth_users SET password_hash = ? WHERE id = ?").run(await hashPassword(newPassword(b, "newPassword")), row.id);
        revokeSessions(row.id, p.sessionId);
        emit({ type: "password-changed", actor: row.id, ip: clientIp(req) });
        ok(res);
      },
    },
    {
      method: "GET",
      path: "/me/sessions",
      handle: ({ req }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const rows = db
          .prepare(
            "SELECT id, method, ip, user_agent, created_at, last_seen_at FROM auth_sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC",
          )
          .all(p.user.id, iso()) as Array<{ id: string; method: string; ip: string; user_agent: string; created_at: string; last_seen_at: string }>;
        return {
          sessions: rows.map((r) => ({
            id: r.id,
            method: r.method,
            ip: r.ip,
            userAgent: r.user_agent,
            createdAt: r.created_at,
            lastSeenAt: r.last_seen_at,
            current: r.id === p.sessionId,
          })),
        };
      },
    },
    {
      method: "DELETE",
      path: "/me/sessions/:id",
      handle: ({ req, res, params }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const r = db.prepare("DELETE FROM auth_sessions WHERE id = ? AND user_id = ?").run(params[0]!, p.user.id);
        if (r.changes === 0) throw new AuthError(404, "not-found", "No such session.");
        ok(res, undefined, params[0] === p.sessionId ? { "set-cookie": clearCookie(C.session) } : undefined);
      },
    },

    // Authenticator app.
    {
      method: "POST",
      path: "/me/totp",
      handle: ({ req }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        if (hasTotp(p.user.id)) throw new AuthError(409, "conflict", "An authenticator app is already set up. Remove it first.");
        const secret = base32(randomBytes(20));
        db.prepare(
          "INSERT INTO auth_totp (user_id, secret, created_at) VALUES (?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at",
        ).run(p.user.id, secrets.seal(secret), iso());
        const label = encodeURIComponent(`${productName}:${p.user.email}`);
        return { secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(productName)}&algorithm=SHA1&digits=6&period=30` };
      },
    },
    {
      method: "POST",
      path: "/me/totp/confirm",
      handle: async ({ req, body }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const row = db.prepare("SELECT secret FROM auth_totp WHERE user_id = ? AND confirmed = 0").get(p.user.id) as { secret: string } | undefined;
        if (!row) throw new AuthError(404, "not-found", "Start setting up the authenticator app first.");
        const step = matchTotp(fromBase32(secrets.open(row.secret)), str(await body(), "code", { max: 16 }), now());
        if (step === null) throw new AuthError(422, "invalid-body", "That code is not valid. Check the time on your phone.");
        db.prepare("UPDATE auth_totp SET confirmed = 1, last_step = ? WHERE user_id = ?").run(step, p.user.id);
        return { recoveryCodes: factorAdded(p, req, "totp") };
      },
    },
    {
      method: "DELETE",
      path: "/me/totp",
      handle: ({ req, res }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        requireStrongSession(p);
        if (db.prepare("DELETE FROM auth_totp WHERE user_id = ?").run(p.user.id).changes === 0)
          throw new AuthError(404, "not-found", "No authenticator app is set up.");
        factorRemoved(p.user.id);
        emit({ type: "mfa-removed", actor: p.user.id, method: "totp", ip: clientIp(req) });
        ok(res);
      },
    },
    {
      method: "POST",
      path: "/me/recovery-codes",
      handle: ({ req }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        requireStrongSession(p);
        if (!hasMfa(p.user.id)) throw new AuthError(409, "conflict", "Add an authenticator app or a passkey first.");
        return { recoveryCodes: newRecoveryCodes(p.user.id) };
      },
    },

    // Passkeys.
    {
      method: "POST",
      path: "/me/passkeys/options",
      handle: async ({ req, res }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const options = await generateRegistrationOptions({
          rpName: productName,
          rpID,
          userName: p.user.email,
          userDisplayName: p.user.name,
          userID: new TextEncoder().encode(p.user.id),
          attestationType: "none",
          excludeCredentials: passkeys(p.user.id).map((k) => ({ id: k.id, transports: JSON.parse(k.transports) as AuthenticatorTransport[] })),
          authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        });
        const id = createChallenge("webauthn-register", p.user.id, { challenge: options.challenge }, 5 * 60_000);
        ok(res, options, { "set-cookie": setCookie(C.webauthn, id, 300) });
      },
    },
    {
      method: "POST",
      path: "/me/passkeys",
      handle: async ({ req, res, body }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        const ch = readChallenge(parseCookies(req.headers.cookie)[C.webauthn], "webauthn-register");
        if (!ch || ch.userId !== p.user.id) throw new AuthError(400, "invalid-body", "The passkey request expired. Try again.");
        dropChallenge(ch.idHash);
        const b = await body();
        const name = str(b, "name", { max: 64, optional: true })?.trim() || "Passkey";
        const v = await verifyRegistrationResponse({
          response: b.response as RegistrationResponseJSON,
          expectedChallenge: String(ch.data.challenge),
          expectedOrigin: [...allowedOrigins],
          expectedRPID: rpID,
          requireUserVerification: false,
        }).catch((err: Error) => {
          throw new AuthError(422, "invalid-body", `The passkey could not be verified: ${err.message}`);
        });
        if (!v.verified) throw new AuthError(422, "invalid-body", "The passkey could not be verified.");
        const c = v.registrationInfo.credential;
        db.prepare("INSERT INTO auth_passkeys (id, user_id, name, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
          c.id,
          p.user.id,
          name,
          c.publicKey,
          c.counter,
          JSON.stringify(c.transports ?? []),
          iso(),
        );
        const codes = factorAdded(p, req, "passkey");
        sendJson(res, 201, { passkey: { id: c.id, name, createdAt: iso() }, recoveryCodes: codes }, { "set-cookie": clearCookie(C.webauthn) });
      },
    },
    {
      method: "DELETE",
      path: "/me/passkeys/:id",
      handle: ({ req, res, params }) => {
        const p = sessionPrincipal(req, "user", { allowMfaSetup: true });
        requireStrongSession(p);
        if (db.prepare("DELETE FROM auth_passkeys WHERE id = ? AND user_id = ?").run(params[0]!, p.user.id).changes === 0)
          throw new AuthError(404, "not-found", "No such passkey.");
        factorRemoved(p.user.id);
        emit({ type: "mfa-removed", actor: p.user.id, method: "passkey", ip: clientIp(req) });
        ok(res);
      },
    },

    // Members (Settings → Members).
    {
      method: "GET",
      path: "/members",
      handle: ({ req }) => {
        authorize(req, "admin");
        const rows = db.prepare("SELECT * FROM auth_users ORDER BY name COLLATE NOCASE").all() as unknown as UserRow[];
        return { members: rows.map(toUser) };
      },
    },
    {
      method: "POST",
      path: "/members",
      handle: async ({ req, res, body }) => {
        const p = sessionPrincipal(req, "admin");
        const b = await body();
        const role = memberRole(b);
        mayManage(p.role, role);
        const email = readEmail(b);
        if (userByEmail(email)) throw new AuthError(409, "conflict", `${email} is already a member.`);
        const user = insertUser({ email, name: str(b, "name", { max: 128, optional: true })?.trim() || email, role, status: "invited" });
        const token = createChallenge("invite", user.id, { kind: "invite" }, 7 * 86_400_000);
        emit({ type: "member-invited", actor: p.user.id, target: user.id, ip: clientIp(req), detail: role });
        sendJson(res, 201, { member: toUser(user), link: links.password(token), linkExpiresAt: iso(now() + 7 * 86_400_000) });
      },
    },
    {
      method: "PATCH",
      path: "/members/:id",
      handle: async ({ req, params, body }) => {
        const p = sessionPrincipal(req, "admin");
        const target = member(params[0]!);
        mayManage(p.role, target.role);
        const b = await body();
        const changes: string[] = [];
        if (b.role !== undefined) {
          const role = memberRole(b);
          mayManage(p.role, role);
          if (target.role === "owner" && role !== "owner" && activeOwnersExcept(target.id) === 0)
            throw new AuthError(409, "conflict", "There must be at least one owner.");
          db.prepare("UPDATE auth_users SET role = ? WHERE id = ?").run(role, target.id);
          changes.push(`role ${target.role} -> ${role}`);
        }
        if (b.status !== undefined) {
          if (b.status !== "active" && b.status !== "disabled") throw new AuthError(422, "invalid-body", "status must be active or disabled.");
          if (target.status === "invited") throw new AuthError(409, "conflict", "An invited member becomes active by accepting the invitation.");
          if (b.status === "disabled") {
            if (target.id === p.user.id) throw new AuthError(409, "conflict", "You cannot disable yourself.");
            if (target.role === "owner" && activeOwnersExcept(target.id) === 0) throw new AuthError(409, "conflict", "There must be at least one owner.");
            revokeSessions(target.id);
          }
          db.prepare("UPDATE auth_users SET status = ? WHERE id = ?").run(b.status, target.id);
          changes.push(`status ${target.status} -> ${b.status}`);
        }
        if (changes.length) emit({ type: "member-updated", actor: p.user.id, target: target.id, ip: clientIp(req), detail: changes.join(", ") });
        return toUser(userRow(target.id)!);
      },
    },
    {
      method: "DELETE",
      path: "/members/:id",
      handle: ({ req, res, params }) => {
        const p = sessionPrincipal(req, "admin");
        const target = member(params[0]!);
        mayManage(p.role, target.role);
        if (target.id === p.user.id) throw new AuthError(409, "conflict", "You cannot remove yourself.");
        if (target.role === "owner" && activeOwnersExcept(target.id) === 0) throw new AuthError(409, "conflict", "There must be at least one owner.");
        db.prepare("DELETE FROM auth_users WHERE id = ?").run(target.id);
        emit({ type: "member-removed", actor: p.user.id, target: target.id, ip: clientIp(req), detail: target.email });
        ok(res);
      },
    },
    // A new password link for someone who forgot theirs, and a reset of their second factors. There is no email
    // yet, so the admin passes the link on.
    {
      method: "POST",
      path: "/members/:id/reset",
      handle: async ({ req, res, params, body }) => {
        const p = sessionPrincipal(req, "admin");
        const target = member(params[0]!);
        mayManage(p.role, target.role);
        if (target.id === p.user.id) throw new AuthError(409, "conflict", "Change your own password and factors under your account.");
        const b = await body();
        // Second factors can still be reset; the password itself is the other directory's.
        if (b.mfa !== true) ownPassword(target.id);
        const mfa = b.mfa === true;
        revokeSessions(target.id);
        if (mfa) {
          db.prepare("DELETE FROM auth_totp WHERE user_id = ?").run(target.id);
          db.prepare("DELETE FROM auth_passkeys WHERE user_id = ?").run(target.id);
          db.prepare("DELETE FROM auth_recovery_codes WHERE user_id = ?").run(target.id);
          emit({ type: "mfa-removed", actor: p.user.id, target: target.id, ip: clientIp(req), detail: "reset by admin" });
        }
        // Someone whose password another directory keeps signs in with it again: there is no link to send.
        if (managedBy(target.id)) {
          emit({ type: "member-updated", actor: p.user.id, target: target.id, ip: clientIp(req), detail: "second factors reset" });
          return sendJson(res, 200, { link: null, linkExpiresAt: null });
        }
        const kind = target.status === "invited" ? "invite" : "reset";
        db.prepare("DELETE FROM auth_challenges WHERE user_id = ? AND kind = ?").run(target.id, kind);
        const token = createChallenge(kind, target.id, { kind }, 86_400_000);
        emit({
          type: "member-updated",
          actor: p.user.id,
          target: target.id,
          ip: clientIp(req),
          detail: mfa ? "password link and second factors reset" : "password link",
        });
        sendJson(res, 200, { link: links.password(token), linkExpiresAt: iso(now() + 86_400_000) });
      },
    },

    // Identity providers (Settings → Sign-in, ADR 0033). Admins see them; only owners change them, because a role
    // mapping can make anyone in a group an owner.
    {
      method: "GET",
      path: "/providers",
      handle: ({ req }) => {
        authorize(req, "admin");
        const rows = providerRows();
        return {
          providers: [...envProviders.map((p) => providerView(p)), ...rows.map((r) => providerView(fromRow(r), r))],
          redirectUriTemplate: `${origin}${PREFIX}/oidc/{id}/callback`,
        };
      },
    },
    {
      method: "POST",
      path: "/providers",
      handle: async ({ req, res, body }) => {
        const p = sessionPrincipal(req, "owner");
        const b = await body();
        const v = providerInput(b);
        const id = b.id === undefined ? v.preset : b.id;
        if (typeof id !== "string" || !/^[a-z0-9-]{1,32}$/.test(id))
          throw new AuthError(422, "invalid-body", "id must be lowercase letters, digits and dashes, up to 32.");
        if (envProviders.some((e) => e.id === id) || providerRow(id))
          throw new AuthError(409, "conflict", `A provider with the id ${id} exists. Choose another id.`);
        onlyAutoRedirect(id, v.autoRedirect);
        db.prepare(
          "INSERT INTO auth_providers (id, preset, name, issuer, client_id, client_secret, scopes, groups_claim, role_mapping, default_role, allowed_domains, enabled, auto_redirect, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(
          id,
          v.preset,
          v.name,
          v.issuer,
          v.clientId,
          v.clientSecret,
          JSON.stringify(v.scopes),
          v.groupsClaim,
          JSON.stringify(v.roleMapping),
          v.defaultRole,
          JSON.stringify(v.allowedDomains),
          v.enabled ? 1 : 0,
          v.autoRedirect ? 1 : 0,
          iso(),
          iso(),
        );
        // Sign-ins kept from an earlier provider with this id are not this one's.
        unlinkProvider(id);
        emit({ type: "provider-added", actor: p.user.id, target: id, ip: clientIp(req), detail: `${v.name} (${v.issuer})` });
        const row = providerRow(id)!;
        sendJson(res, 201, providerView(fromRow(row), row));
      },
    },
    {
      method: "PATCH",
      path: "/providers/:id",
      handle: async ({ req, params, body }) => {
        const p = sessionPrincipal(req, "owner");
        const id = params[0]!;
        if (envProviders.some((e) => e.id === id)) throw new AuthError(409, "conflict", `${id} is set in the environment; change it there.`);
        const current = providerRow(id);
        if (!current) throw new AuthError(404, "not-found", "No such provider.");
        const v = providerInput(await body(), current);
        onlyAutoRedirect(id, v.autoRedirect);
        db.prepare(
          "UPDATE auth_providers SET name = ?, issuer = ?, client_id = ?, client_secret = ?, scopes = ?, groups_claim = ?, role_mapping = ?, default_role = ?, allowed_domains = ?, enabled = ?, auto_redirect = ?, updated_at = ? WHERE id = ?",
        ).run(
          v.name,
          v.issuer,
          v.clientId,
          v.clientSecret,
          JSON.stringify(v.scopes),
          v.groupsClaim,
          JSON.stringify(v.roleMapping),
          v.defaultRole,
          JSON.stringify(v.allowedDomains),
          v.enabled ? 1 : 0,
          v.autoRedirect ? 1 : 0,
          iso(),
          id,
        );
        if (v.issuer !== current.issuer) unlinkProvider(id);
        oidc.forget(id);
        emit({
          type: "provider-updated",
          actor: p.user.id,
          target: id,
          ip: clientIp(req),
          detail: v.issuer !== current.issuer ? `issuer ${current.issuer} -> ${v.issuer}` : undefined,
        });
        const row = providerRow(id)!;
        return providerView(fromRow(row), row);
      },
    },
    {
      method: "DELETE",
      path: "/providers/:id",
      handle: ({ req, res, params }) => {
        const p = sessionPrincipal(req, "owner");
        const id = params[0]!;
        if (envProviders.some((e) => e.id === id)) throw new AuthError(409, "conflict", `${id} is set in the environment; remove it there.`);
        if (db.prepare("DELETE FROM auth_providers WHERE id = ?").run(id).changes === 0) throw new AuthError(404, "not-found", "No such provider.");
        unlinkProvider(id);
        oidc.forget(id);
        emit({ type: "provider-removed", actor: p.user.id, target: id, ip: clientIp(req) });
        ok(res);
      },
    },
    {
      // Reads the discovery document before a provider is saved, so a wrong issuer shows at once.
      method: "POST",
      path: "/providers/discover",
      handle: async ({ req, body }) => {
        sessionPrincipal(req, "owner");
        const issuer = str(await body(), "issuer", { max: 512 }).trim();
        try {
          validateProvider({ id: "check", name: "", issuer, clientId: "", allowInsecure: opts.allowInsecureIssuers });
        } catch (err) {
          throw new AuthError(422, "invalid-body", (err as Error).message.replace('for "check" ', ""));
        }
        return await oidc.discover(issuer, !!opts.allowInsecureIssuers).catch((err: Error) => {
          throw new AuthError(422, "invalid-body", `No OpenID provider answers at ${issuer}: ${err.message}`);
        });
      },
    },

    // API tokens (ADR 0003): scoped to this product and one role, always with an expiry, shown once.
    {
      method: "GET",
      path: "/tokens",
      handle: ({ req }) => {
        authorize(req, "admin");
        const rows = db
          .prepare("SELECT t.*, u.email AS creator FROM auth_tokens t LEFT JOIN auth_users u ON u.id = t.created_by ORDER BY t.created_at DESC")
          .all() as Array<{
          id: string;
          name: string;
          role: Role;
          creator: string | null;
          created_at: string;
          expires_at: string;
          last_used_at: string | null;
        }>;
        return {
          tokens: rows.map((r) => ({
            id: r.id,
            name: r.name,
            role: r.role,
            createdBy: r.creator,
            createdAt: r.created_at,
            expiresAt: r.expires_at,
            lastUsedAt: r.last_used_at,
            expired: r.expires_at <= iso(),
          })),
        };
      },
    },
    {
      method: "POST",
      path: "/tokens",
      handle: async ({ req, res, body }) => {
        const p = sessionPrincipal(req, "admin");
        const b = await body();
        const name = str(b, "name", { max: 64 }).trim();
        const role = b.role;
        if (role !== "admin" && role !== "editor" && role !== "viewer") throw new AuthError(422, "invalid-body", "role must be admin, editor or viewer.");
        if (!atLeast(p.role, role)) throw new AuthError(403, "forbidden", "A token cannot have a higher role than yours.");
        const days = b.expiresInDays ?? 90;
        if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 366)
          throw new AuthError(422, "invalid-body", "expiresInDays must be a whole number from 1 to 366.");
        const secret = `oa_${product}_${randomToken()}`;
        const id = randomUUID();
        const expiresAt = iso(now() + days * 86_400_000);
        db.prepare("INSERT INTO auth_tokens (id, secret_hash, name, role, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
          id,
          sha256(secret),
          name,
          role,
          p.user.id,
          iso(),
          expiresAt,
        );
        emit({ type: "token-created", actor: p.user.id, target: id, ip: clientIp(req), detail: `${name} (${role}, ${days} days)` });
        sendJson(res, 201, { id, name, role, expiresAt, token: secret });
      },
    },
    {
      method: "DELETE",
      path: "/tokens/:id",
      handle: ({ req, res, params }) => {
        const p = sessionPrincipal(req, "admin");
        if (db.prepare("DELETE FROM auth_tokens WHERE id = ?").run(params[0]!).changes === 0) throw new AuthError(404, "not-found", "No such token.");
        emit({ type: "token-revoked", actor: p.user.id, target: params[0], ip: clientIp(req) });
        ok(res);
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${PREFIX}${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  return {
    /** Answers requests under /api/v1/auth and returns true; returns false for every other path. */
    async handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (!url.pathname.startsWith(`${PREFIX}/`)) return false;
      const cors = preferenceOrigin(req);
      if (cors) {
        res.setHeader("access-control-allow-origin", cors);
        res.setHeader("access-control-allow-credentials", "true");
        res.setHeader("vary", "origin");
        if (req.method === "OPTIONS") {
          res
            .writeHead(204, { "access-control-allow-methods": "GET, PATCH", "access-control-allow-headers": "content-type", "access-control-max-age": "600" })
            .end();
          return true;
        }
      }
      for (const r of compiled) {
        const m = url.pathname.match(r.re);
        if (!m || r.method !== req.method) continue;
        try {
          const result = await r.handle({ req, res, url, params: m.slice(1).map(decodeURIComponent), body: () => readJson(req) });
          if (!res.headersSent) result === undefined ? ok(res) : ok(res, result);
        } catch (err) {
          if (!(err instanceof AuthError)) throw err;
          sendProblem(res, err);
          if (!req.complete) req.resume();
        }
        return true;
      }
      sendProblem(res, new AuthError(404, "not-found"));
      return true;
    },

    authorize,

    /** Route names for metrics: the matched pattern, never ids or tokens. */
    routeName(req: IncomingMessage): string | undefined {
      const path = new URL(req.url ?? "/", "http://localhost").pathname;
      const r = compiled.find((c) => c.method === req.method && c.re.test(path));
      return r && PREFIX + r.path;
    },

    /**
     * On first start, a one-time link that creates the owner (ADR 0013). Returns undefined once someone exists.
     * Every call replaces the previous link, so only the latest one printed works.
     */
    setupLink(): string | undefined {
      if (userCount() > 0) return undefined;
      db.prepare("DELETE FROM auth_challenges WHERE kind = 'setup'").run();
      return links.setup(createChallenge("setup", null, {}, 7 * 86_400_000));
    },

    /** Deletes expired sessions and challenges. Call it every few minutes. */
    purge() {
      const t = iso();
      db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ? OR last_seen_at <= ?").run(t, iso(now() - idleMs));
      db.prepare("DELETE FROM auth_challenges WHERE expires_at <= ?").run(t);
    },

    /** True when TOTP secrets are stored in clear because no secrets key was given. */
    secretsInClear: !opts.secretsKey,
  };
}

export type Auth = ReturnType<typeof createAuth>;
