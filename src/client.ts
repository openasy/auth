// Browser side of @openasy/auth: typed calls to /api/v1/auth for a product's web UI. The session lives in an
// HttpOnly cookie, so nothing here stores a secret.
import { browserSupportsWebAuthn, startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { Role } from "./roles.ts";

export type { Role } from "./roles.ts";

export interface Methods {
  passwords: boolean;
  passkeys: boolean;
  /** Members may have the user role (Identity's directory). */
  users: boolean;
  providers: Array<{ id: string; name: string }>;
  setupRequired: boolean;
}

export interface Member {
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

export interface Me {
  user: Member;
  session: { id: string; method: string; mfa: boolean };
  mfaSetupRequired: boolean;
  hasPassword: boolean;
  passkeys: Array<{ id: string; name: string; createdAt: string; lastUsedAt: string | null }>;
  recoveryCodesLeft: number;
}

export type SignInResult =
  | { status: "signed-in"; user: Member; mfaSetupRequired: boolean }
  | { status: "mfa-required"; methods: Array<"totp" | "passkey" | "recovery-code"> };

export interface Session {
  id: string;
  method: string;
  ip: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

export interface ApiToken {
  id: string;
  name: string;
  role: Exclude<Role, "owner">;
  createdBy: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  expired: boolean;
}

/** A failed call, with the stable problem code from the API (`invalid-credentials`, `mfa-setup-required`...). */
/** An identity provider as Settings → Sign-in shows it. The client secret is never sent back. */
export interface Provider {
  id: string;
  name: string;
  preset: string;
  source: "settings" | "environment";
  enabled: boolean;
  issuer: string;
  clientId: string;
  hasClientSecret: boolean;
  scopes: string[];
  groupsClaim: string | null;
  roleMapping: Record<string, Role>;
  defaultRole: Role | null;
  allowedDomains: string[];
  redirectUri: string;
  createdAt: string | null;
  updatedAt: string | null;
}

/** What to add or change; fields left out keep their value. `clientSecret: null` removes it. */
export interface ProviderChange {
  preset?: string;
  id?: string;
  name?: string;
  issuer?: string;
  clientId?: string;
  clientSecret?: string | null;
  scopes?: string[];
  groupsClaim?: string | null;
  roleMapping?: Record<string, Role>;
  defaultRole?: Role | null;
  allowedDomains?: string[];
  enabled?: boolean;
}

export class AuthApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const BASE = "/api/v1/auth";

async function call<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(BASE + path, {
    method: init.method ?? (init.body === undefined ? "GET" : "POST"),
    credentials: "same-origin",
    headers: init.body === undefined ? undefined : { "content-type": "application/json" },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new AuthApiError(res.status, p.code ?? "error", p.detail ?? p.title ?? `${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export const passkeysSupported = () => browserSupportsWebAuthn();

export const auth = {
  methods: () => call<Methods>("/methods"),
  setup: (b: { token: string; name: string; email: string; password: string }) => call<SignInResult & { status: "signed-in" }>("/setup", { body: b }),
  signIn: (email: string, password: string) => call<SignInResult>("/login", { body: { email, password } }),
  verifyCode: (code: string) => call<SignInResult & { status: "signed-in" }>("/login/mfa", { body: { code } }),
  useRecoveryCode: (recoveryCode: string) => call<SignInResult & { status: "signed-in" }>("/login/mfa", { body: { recoveryCode } }),
  /** Alone, or as the second step after a password. Throws if the person cancels the browser's prompt. */
  async signInWithPasskey() {
    const optionsJSON = await call<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("/login/passkey/options", { body: {} });
    const response = await startAuthentication({ optionsJSON });
    return call<SignInResult & { status: "signed-in" }>("/login/passkey", { body: { response } });
  },
  /** With the one-time setup link: the person becomes the owner through the provider. */
  setupWith(providerId: string, token: string) {
    location.assign(`${BASE}/oidc/${encodeURIComponent(providerId)}/start?setup=${encodeURIComponent(token)}`);
  },
  /** Full-page navigation to the identity provider; the browser comes back signed in. */
  signInWith(providerId: string, returnTo = location.pathname + location.hash) {
    location.assign(`${BASE}/oidc/${encodeURIComponent(providerId)}/start?return=${encodeURIComponent(returnTo)}`);
  },
  signOut: () => call<void>("/logout", { body: {} }),

  link: (token: string) => call<{ kind: "invite" | "reset"; email: string; name: string; productName: string }>(`/links/${encodeURIComponent(token)}`),
  acceptLink: (token: string, password: string, name?: string) => call<SignInResult & { status: "signed-in" }>(`/links/${encodeURIComponent(token)}`, { body: { password, name } }),

  me: () => call<Me>("/me"),
  rename: (name: string) => call<Member>("/me", { method: "PATCH", body: { name } }),
  changePassword: (currentPassword: string, newPassword: string) => call<void>("/me/password", { body: { currentPassword, newPassword } }),
  sessions: () => call<{ sessions: Session[] }>("/me/sessions").then((r) => r.sessions),
  revokeSession: (id: string) => call<void>(`/me/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),

  startTotp: () => call<{ secret: string; uri: string }>("/me/totp", { body: {} }),
  /** Returns recovery codes when this is the first second factor; show them once. */
  confirmTotp: (code: string) => call<{ recoveryCodes?: string[] }>("/me/totp/confirm", { body: { code } }),
  removeTotp: () => call<void>("/me/totp", { method: "DELETE" }),
  async addPasskey(name?: string) {
    const optionsJSON = await call<Parameters<typeof startRegistration>[0]["optionsJSON"]>("/me/passkeys/options", { body: {} });
    const response = await startRegistration({ optionsJSON });
    return call<{ passkey: { id: string; name: string; createdAt: string }; recoveryCodes?: string[] }>("/me/passkeys", { body: { response, name } });
  },
  removePasskey: (id: string) => call<void>(`/me/passkeys/${encodeURIComponent(id)}`, { method: "DELETE" }),
  newRecoveryCodes: () => call<{ recoveryCodes: string[] }>("/me/recovery-codes", { body: {} }).then((r) => r.recoveryCodes),

  members: () => call<{ members: Member[] }>("/members").then((r) => r.members),
  invite: (b: { email: string; name?: string; role: Role }) => call<{ member: Member; link: string; linkExpiresAt: string }>("/members", { body: b }),
  updateMember: (id: string, b: { role?: Role; status?: "active" | "disabled" }) => call<Member>(`/members/${encodeURIComponent(id)}`, { method: "PATCH", body: b }),
  removeMember: (id: string) => call<void>(`/members/${encodeURIComponent(id)}`, { method: "DELETE" }),
  resetMember: (id: string, opts: { mfa?: boolean } = {}) => call<{ link: string; linkExpiresAt: string }>(`/members/${encodeURIComponent(id)}/reset`, { body: opts }),

  tokens: () => call<{ tokens: ApiToken[] }>("/tokens").then((r) => r.tokens),
  /** The secret is in `token` and is never shown again. */
  createToken: (b: { name: string; role: ApiToken["role"]; expiresInDays?: number }) => call<{ id: string; name: string; role: ApiToken["role"]; expiresAt: string; token: string }>("/tokens", { body: b }),
  revokeToken: (id: string) => call<void>(`/tokens/${encodeURIComponent(id)}`, { method: "DELETE" }),

  providers: () => call<{ providers: Provider[]; redirectUriTemplate: string }>("/providers"),
  addProvider: (b: ProviderChange) => call<Provider>("/providers", { body: b }),
  updateProvider: (id: string, b: ProviderChange) => call<Provider>(`/providers/${encodeURIComponent(id)}`, { method: "PATCH", body: b }),
  removeProvider: (id: string) => call<void>(`/providers/${encodeURIComponent(id)}`, { method: "DELETE" }),
  discoverProvider: (issuer: string) => call<{ issuer: string; authorizationEndpoint: string | null; userinfoEndpoint: string | null; scopes: string[] | null; pkce: boolean }>("/providers/discover", { body: { issuer } }),
};

/**
 * Reads and removes `?setup=`, `?link=` and `?auth_error=` from the address bar, so one-time tokens do not stay in
 * history or get copied along with the URL.
 */
export function takeAuthParams(): { setup?: string; link?: string; error?: string } {
  const url = new URL(location.href);
  const out = { setup: url.searchParams.get("setup") ?? undefined, link: url.searchParams.get("link") ?? undefined, error: url.searchParams.get("auth_error") ?? undefined };
  if (out.setup || out.link || out.error) {
    for (const k of ["setup", "link", "auth_error"]) url.searchParams.delete(k);
    history.replaceState(history.state, "", url.pathname + url.search + url.hash);
  }
  return out;
}
