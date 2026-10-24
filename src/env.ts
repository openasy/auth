import { createHash } from "node:crypto";
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

/** The install's brand (ADR 0053), the same in every product: shown under the product's name, on buttons and links. */
export interface BrandSettings {
  organization?: string;
  /** #rrggbb. */
  accent?: string;
  /** The pictures, read once at start and served from the product's own address. */
  logo?: BrandPicture;
  /** The browser tab's icon. */
  favicon?: BrandPicture;
  /** Where people get help: an email address or an https address (OPENASY_SUPPORT). OpenAsy's own when left out. */
  support?: string;
}
export interface BrandPicture {
  body: Buffer;
  type: PictureType;
  etag: string;
}
type PictureType = "image/svg+xml" | "image/png" | "image/webp" | "image/x-icon";

/** What a picture is, from its first bytes rather than its name. */
function pictureType(body: Buffer): PictureType | undefined {
  if (body.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
  if (body.subarray(0, 4).toString("latin1") === "RIFF" && body.subarray(8, 12).toString("latin1") === "WEBP") return "image/webp";
  if (body.subarray(0, 4).equals(Buffer.from([0, 0, 1, 0]))) return "image/x-icon";
  if (/<svg[\s>]/i.test(body.subarray(0, 4096).toString("utf8"))) return "image/svg+xml";
  return undefined;
}

const PICTURES = {
  OPENASY_LOGO: {
    max: 512 * 1024,
    types: ["image/svg+xml", "image/png", "image/webp"],
    kinds: "an SVG, PNG or WebP picture",
    example: "/config/brand/logo.svg",
  },
  OPENASY_FAVICON: {
    max: 128 * 1024,
    types: ["image/svg+xml", "image/png", "image/x-icon"],
    kinds: "an SVG, PNG or ICO icon",
    example: "/config/brand/favicon.png",
  },
} as const;

/**
 * The brand from OPENASY_ORGANIZATION, OPENASY_ACCENT, OPENASY_LOGO, OPENASY_FAVICON and OPENASY_SUPPORT, which the install keeps in
 * config/brand.env. A setting that cannot be used is left out with a warning: the product starts with its own look.
 */
export function brandFromEnv(env: Record<string, string | undefined>): BrandSettings {
  const brand: BrandSettings = {};
  const warn = (message: string) => process.emitWarning(message, { code: "OPENASY_BRAND" });
  const organization = env.OPENASY_ORGANIZATION?.trim();
  if (organization) {
    if (organization.length > 80) warn("OPENASY_ORGANIZATION is longer than 80 characters; it is left out.");
    else brand.organization = organization;
  }
  const accent = env.OPENASY_ACCENT?.trim();
  if (accent) {
    if (/^#[0-9a-f]{6}$/i.test(accent)) brand.accent = accent.toLowerCase();
    else warn(`OPENASY_ACCENT is a color such as #0a66c2, not "${accent}"; it is left out.`);
  }
  const support = env.OPENASY_SUPPORT?.trim();
  if (support) {
    if (/^[^\s@/]+@[^\s@/]+\.[^\s@/]+$/.test(support) || /^https:\/\/[^\s]+$/i.test(support)) brand.support = support;
    else warn(`OPENASY_SUPPORT is an email address or an https address, not "${support}"; it is left out.`);
  }
  const picture = (name: keyof typeof PICTURES): BrandPicture | undefined => {
    const path = env[name]?.trim();
    if (!path) return undefined;
    const { max, types, kinds, example } = PICTURES[name];
    if (/^[a-z]+:\/\//i.test(path)) return void warn(`${name} is a file mounted into the container, such as ${example}, not an address; it is left out.`);
    if (!existsSync(path)) return void warn(`${name}: ${path} is not in the container; mount it there. It is left out.`);
    const body = readFileSync(path);
    const type = pictureType(body);
    if (body.length > max) return void warn(`${name}: ${path} is larger than ${max / 1024} KB; it is left out.`);
    if (!type || !(types as readonly string[]).includes(type)) return void warn(`${name}: ${path} is not ${kinds}; it is left out.`);
    return { body, type, etag: createHash("sha256").update(body).digest("base64url").slice(0, 16) };
  };
  const logo = picture("OPENASY_LOGO");
  if (logo) brand.logo = logo;
  const favicon = picture("OPENASY_FAVICON");
  if (favicon) brand.favicon = favicon;
  return brand;
}
