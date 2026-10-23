import { existsSync, readFileSync } from "node:fs";
import type { OidcProvider } from "./oidc.ts";
import { PRESETS, preset } from "./presets.ts";
import { isRole, type Role } from "./roles.ts";

/**
 * One OIDC provider from environment variables, with the same names in every product of an install, like
 * OPENASY_PRODUCTS. Only the client differs from product to product, because each one is its own application at the
 * provider:
 *
 *   OPENASY_OIDC_ISSUER, OPENASY_OIDC_CLIENT_ID, OPENASY_OIDC_CLIENT_SECRET   required to turn it on
 *   OPENASY_OIDC_PROVIDER        keycloak, entra, okta, google, authentik, zitadel or openasy-identity: its name, scopes
 *                                and groups claim become the defaults of the three below
 *   OPENASY_OIDC_NAME            on the button, default "SSO"
 *   OPENASY_OIDC_SCOPES          space-separated, default "openid email profile"
 *   OPENASY_OIDC_GROUPS_CLAIM    default "groups"; a dotted path such as realm_access.roles reads nested claims
 *   OPENASY_OIDC_ROLE_MAPPING    "group=role,group=role", for example "openasy-admins=admin,staff=viewer"
 *   OPENASY_OIDC_DEFAULT_ROLE    role for people nobody invited; unset means they are refused
 *   OPENASY_OIDC_ALLOWED_DOMAINS comma-separated email domains
 *   OPENASY_OIDC_AUTO_REDIRECT   true: the sign-in screen goes straight to the provider; default false
 *
 * Until 0.5.0 the names had the product's prefix, such as VPN_OIDC_ISSUER. With `legacyPrefix` those are still read
 * when the shared name is unset, with a deprecation warning; they go in a later release.
 */
export function oidcFromEnv(env: Record<string, string | undefined>, legacyPrefix?: string): OidcProvider[] {
  const legacy: string[] = [];
  const name = (n: string) => `OPENASY_OIDC_${n}`;
  const v = (n: string) => {
    const value = env[name(n)]?.trim();
    if (value) return value;
    const old = legacyPrefix && env[`${legacyPrefix}OIDC_${n}`]?.trim();
    if (!old) return undefined;
    legacy.push(`${legacyPrefix}OIDC_${n}`);
    return old;
  };
  const issuer = v("ISSUER");
  if (!issuer) return [];
  const clientId = v("CLIENT_ID");
  if (!clientId) throw new Error(`${name("CLIENT_ID")} is required with ${name("ISSUER")}`);
  const role = (value: string, what: string): Role => {
    if (!isRole(value)) throw new Error(`${what}: "${value}" is not owner, admin, editor, viewer or user`);
    return value;
  };
  const presetId = v("PROVIDER");
  const p = presetId ? preset(presetId) : undefined;
  if (presetId && !p) throw new Error(`${name("PROVIDER")}: "${presetId}" is not one of ${PRESETS.map((x) => x.id).join(", ")}`);
  const mapping = v("ROLE_MAPPING");
  const defaultRole = v("DEFAULT_ROLE");
  const autoRedirect = env[name("AUTO_REDIRECT")]?.trim() || undefined;
  if (autoRedirect && autoRedirect !== "true" && autoRedirect !== "false")
    throw new Error(`${name("AUTO_REDIRECT")} must be true or false, not "${autoRedirect}"`);
  const provider: OidcProvider = {
    id: "sso",
    name: v("NAME") ?? p?.name ?? "SSO",
    issuer,
    clientId,
    clientSecret: v("CLIENT_SECRET"),
    scopes: v("SCOPES")?.split(/\s+/) ?? p?.scopes,
    groupsClaim: v("GROUPS_CLAIM") ?? p?.groupsClaim,
    roleMapping: mapping
      ? Object.fromEntries(
          mapping.split(",").map((pair) => {
            const [group, r] = pair.split("=").map((s) => s.trim());
            if (!group || !r) throw new Error(`${name("ROLE_MAPPING")} must look like "group=role,group=role"`);
            return [group, role(r, name("ROLE_MAPPING"))];
          }),
        )
      : undefined,
    defaultRole: defaultRole ? role(defaultRole, name("DEFAULT_ROLE")) : undefined,
    allowedDomains: v("ALLOWED_DOMAINS")
      ?.split(",")
      .map((d) => d.trim().toLowerCase()),
    autoRedirect: autoRedirect === "true" || undefined,
  };
  if (legacy.length) {
    const renamed = legacy.map((x) => `${x} -> ${x.replace(legacyPrefix!, "OPENASY_")}`).join(", ");
    process.emitWarning(`Rename these variables, the old names go in a later release: ${renamed}`, { type: "DeprecationWarning", code: "OPENASY_OIDC_ENV" });
  }
  return [provider];
}

/**
 * The 32-byte key that encrypts secrets at rest (ADR 0021), from a mounted file: 32 raw bytes, 64 hex characters or
 * base64. Returns undefined when the file does not exist.
 */
export function readSecretsKey(path: string): Buffer | undefined {
  if (!existsSync(path)) return undefined;
  const raw = readFileSync(path);
  const text = raw.toString("utf8").trim();
  const key = raw.length === 32 ? raw : /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (key.length !== 32) throw new Error(`${path} must hold a 32-byte key (raw, 64 hex characters or base64); generate one with: openssl rand -hex 32`);
  return key;
}
