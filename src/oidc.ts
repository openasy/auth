import * as client from "openid-client";
import { AuthError } from "./http.ts";
import type { Role } from "./roles.ts";

export interface OidcProvider {
  /** Used in URLs: /api/v1/auth/oidc/<id>/start. Lowercase letters, digits and dashes. */
  id: string;
  /** On the sign-in button: "Continue with <name>". */
  name: string;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  /** Default: openid email profile. Add groups (or what the IdP calls it) for role mapping. */
  scopes?: string[];
  /**
   * Where group names are: a claim name, or a dotted path into nested claims such as realm_access.roles. A list,
   * one name, or an object whose keys are the names (ZITADEL's roles). Default: groups.
   */
  groupsClaim?: string;
  /**
   * IdP group to role (ADR 0003). When set, the role follows the groups on every sign-in, and people in none of
   * the groups are refused unless `defaultRole` is set.
   */
  roleMapping?: Record<string, Role>;
  /** Role for people signing in for the first time without an invitation. Unset: only known people may sign in. */
  defaultRole?: Role;
  /** Only accept these email domains, for IdPs where anyone can have an account (Google, GitHub). */
  allowedDomains?: string[];
  /** For tests and local IdPs only: allow an http:// issuer. */
  allowInsecure?: boolean;
  /**
   * The sign-in screen goes straight to this provider instead of showing its form, except after signing out, after a
   * failed sign-in, and with ?local=1. Only one provider may have it.
   */
  autoRedirect?: boolean;
  /**
   * The preset it was set up from, such as keycloak. With openasy-identity, Identity keeps the people who sign in
   * through it: their account, their role through groups, their theme and their language (ADR 0033).
   */
  preset?: string;
}

export interface OidcClaims {
  subject: string;
  email: string | undefined;
  emailVerified: boolean;
  name: string | undefined;
  groups: string[];
  /** The provider had too many groups for the token and left them out (Microsoft Entra ID). */
  groupsOverage: boolean;
}

/** The value at a claim name, or else at a dotted path into nested claims. */
export function claimAt(claims: Record<string, unknown>, path: string): unknown {
  if (path in claims) return claims[path];
  let v: unknown = claims;
  for (const part of path.split(".")) {
    if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
    v = (v as Record<string, unknown>)[part];
  }
  return v;
}

/** Group names from a claim value: a list, one name, or an object whose keys are the names. */
export function groupNames(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((g): g is string => typeof g === "string");
  if (typeof raw === "string") return [raw];
  if (raw && typeof raw === "object") return Object.keys(raw);
  return [];
}

export function validateProvider(p: OidcProvider) {
  if (!/^[a-z0-9-]{1,32}$/.test(p.id)) throw new Error(`OIDC provider id "${p.id}" must be lowercase letters, digits and dashes`);
  const issuer = new URL(p.issuer);
  if (issuer.protocol !== "https:" && !p.allowInsecure) throw new Error(`OIDC issuer for "${p.id}" must use https`);
}

export function createOidc(redirectUri: (id: string) => string) {
  const configs = new Map<string, Promise<client.Configuration>>();

  function config(p: OidcProvider) {
    let c = configs.get(p.id);
    if (!c) {
      c = client.discovery(new URL(p.issuer), p.clientId, p.clientSecret, undefined, p.allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined);
      // A failed discovery is retried on the next sign-in instead of being cached.
      c.catch(() => configs.delete(p.id));
      configs.set(p.id, c);
    }
    return c;
  }

  return {
    /** Drops what was discovered about a provider, after its settings changed. */
    forget(id: string) {
      configs.delete(id);
    },

    /** Reads a provider's discovery document, to check its issuer before it is saved. */
    async discover(issuer: string, allowInsecure: boolean) {
      const cfg = await client.discovery(
        new URL(issuer),
        "openasy-check",
        undefined,
        undefined,
        allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined,
      );
      const m = cfg.serverMetadata();
      return {
        issuer: m.issuer,
        authorizationEndpoint: m.authorization_endpoint ?? null,
        userinfoEndpoint: m.userinfo_endpoint ?? null,
        scopes: m.scopes_supported ?? null,
        pkce: (m.code_challenge_methods_supported ?? []).includes("S256"),
      };
    },

    /** The IdP URL to send the browser to, and what must be kept until the callback. */
    async start(p: OidcProvider) {
      const cfg = await config(p).catch((err: Error) => {
        throw new AuthError(503, "not-configured", `${p.name} could not be reached: ${err.message}`);
      });
      const verifier = client.randomPKCECodeVerifier();
      const state = client.randomState();
      const nonce = client.randomNonce();
      const url = client.buildAuthorizationUrl(cfg, {
        redirect_uri: redirectUri(p.id),
        scope: (p.scopes ?? ["openid", "email", "profile"]).join(" "),
        code_challenge: await client.calculatePKCECodeChallenge(verifier),
        code_challenge_method: "S256",
        state,
        nonce,
      });
      return { url: url.href, verifier, state, nonce };
    },

    /** Checks the callback (state, nonce, PKCE, ID token signature and audience) and returns the claims. */
    async finish(p: OidcProvider, callbackUrl: URL, checks: { verifier: string; state: string; nonce: string }): Promise<OidcClaims> {
      const cfg = await config(p);
      const tokens = await client.authorizationCodeGrant(cfg, callbackUrl, {
        pkceCodeVerifier: checks.verifier,
        expectedState: checks.state,
        expectedNonce: checks.nonce,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (!claims) throw new Error("the provider returned no ID token");
      const path = p.groupsClaim ?? "groups";
      let raw = claimAt(claims, path);
      // Some providers put groups only in userinfo (authentik, Okta with some authorization servers).
      if (raw === undefined && cfg.serverMetadata().userinfo_endpoint && tokens.access_token) {
        const info = await client.fetchUserInfo(cfg, tokens.access_token, claims.sub).catch(() => undefined);
        if (info) raw = claimAt(info, path);
      }
      const names = claims._claim_names as Record<string, unknown> | undefined;
      return {
        subject: claims.sub,
        email: typeof claims.email === "string" ? claims.email.toLowerCase() : undefined,
        emailVerified: claims.email_verified === true,
        name: typeof claims.name === "string" ? claims.name : undefined,
        groups: groupNames(raw),
        groupsOverage: raw === undefined && !!names && path in names,
      };
    },
  };
}
