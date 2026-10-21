import { existsSync, readFileSync } from "node:fs";
import type { OidcProvider } from "./oidc.ts";
import { PRESETS, preset } from "./presets.ts";
import { isRole, type Role } from "./roles.ts";

/**
 * One OIDC provider from environment variables, the same names in every product with its own prefix:
 *
 *   <P>OIDC_ISSUER, <P>OIDC_CLIENT_ID, <P>OIDC_CLIENT_SECRET   required to turn it on
 *   <P>OIDC_PROVIDER        keycloak, entra, okta, google, authentik, zitadel or openasy-identity: its name, scopes
 *                           and groups claim become the defaults of the three below
 *   <P>OIDC_NAME            on the button, default "SSO"
 *   <P>OIDC_SCOPES          space-separated, default "openid email profile"
 *   <P>OIDC_GROUPS_CLAIM    default "groups"; a dotted path such as realm_access.roles reads nested claims
 *   <P>OIDC_ROLE_MAPPING    "group=role,group=role", for example "vulns-admins=admin,staff=viewer"
 *   <P>OIDC_DEFAULT_ROLE    role for people nobody invited; unset means they are refused
 *   <P>OIDC_ALLOWED_DOMAINS comma-separated email domains
 */
export function oidcFromEnv(env: Record<string, string | undefined>, prefix: string): OidcProvider[] {
  const v = (name: string) => env[`${prefix}OIDC_${name}`]?.trim() || undefined;
  const issuer = v("ISSUER");
  if (!issuer) return [];
  const clientId = v("CLIENT_ID");
  if (!clientId) throw new Error(`${prefix}OIDC_CLIENT_ID is required with ${prefix}OIDC_ISSUER`);
  const role = (value: string, what: string): Role => {
    if (!isRole(value)) throw new Error(`${what}: "${value}" is not owner, admin, editor or viewer`);
    return value;
  };
  const presetId = v("PROVIDER");
  const p = presetId ? preset(presetId) : undefined;
  if (presetId && !p) throw new Error(`${prefix}OIDC_PROVIDER: "${presetId}" is not one of ${PRESETS.map((x) => x.id).join(", ")}`);
  const mapping = v("ROLE_MAPPING");
  const defaultRole = v("DEFAULT_ROLE");
  return [
    {
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
              if (!group || !r) throw new Error(`${prefix}OIDC_ROLE_MAPPING must look like "group=role,group=role"`);
              return [group, role(r, `${prefix}OIDC_ROLE_MAPPING`)];
            }),
          )
        : undefined,
      defaultRole: defaultRole ? role(defaultRole, `${prefix}OIDC_DEFAULT_ROLE`) : undefined,
      allowedDomains: v("ALLOWED_DOMAINS")?.split(",").map((d) => d.trim().toLowerCase()),
    },
  ];
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
