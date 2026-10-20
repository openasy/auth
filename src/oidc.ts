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
  /** The claim holding group names. Default: groups. */
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
}

export interface OidcClaims {
  subject: string;
  email: string | undefined;
  emailVerified: boolean;
  name: string | undefined;
  groups: string[];
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
      const raw = claims[p.groupsClaim ?? "groups"];
      return {
        subject: claims.sub,
        email: typeof claims.email === "string" ? claims.email.toLowerCase() : undefined,
        emailVerified: claims.email_verified === true,
        name: typeof claims.name === "string" ? claims.name : undefined,
        groups: Array.isArray(raw) ? raw.filter((g): g is string => typeof g === "string") : typeof raw === "string" ? [raw] : [],
      };
    },
  };
}
