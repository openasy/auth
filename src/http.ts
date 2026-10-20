import type { IncomingMessage, ServerResponse } from "node:http";

export type AuthProblem =
  | "unauthenticated"
  | "invalid-credentials"
  | "invalid-token"
  | "mfa-required"
  | "mfa-setup-required"
  | "forbidden"
  | "cross-site"
  | "invalid-json"
  | "invalid-body"
  | "not-found"
  | "conflict"
  | "rate-limited"
  | "not-configured";

const TITLES: Record<AuthProblem, string> = {
  unauthenticated: "Sign-in required",
  "invalid-credentials": "Invalid credentials",
  "invalid-token": "Invalid token",
  "mfa-required": "Second factor required",
  "mfa-setup-required": "Two-step verification must be set up",
  forbidden: "Forbidden",
  "cross-site": "Cross-site request refused",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "rate-limited": "Too many attempts",
  "not-configured": "Not configured",
};

/** Thrown by the auth routes and by `authorize()`. Products render it with `sendProblem`. */
export class AuthError extends Error {
  readonly status: number;
  readonly code: AuthProblem;
  readonly title: string;
  constructor(status: number, code: AuthProblem, detail?: string) {
    super(detail ?? TITLES[code]);
    this.status = status;
    this.code = code;
    this.title = TITLES[code];
  }
}

export const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
};

export function sendJson(res: ServerResponse, status: number, data: unknown, headers: Record<string, string | string[]> = {}) {
  const body = data === undefined ? "" : JSON.stringify(data);
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, ...(body && { "content-type": "application/json", "content-length": Buffer.byteLength(body) }) });
  res.end(body);
}

/** RFC 9457 Problem Details, in the same shape every product uses (ADR 0024). */
export function sendProblem(res: ServerResponse, err: AuthError, headers: Record<string, string | string[]> = {}) {
  const body = JSON.stringify({ type: `https://openasy.github.io/problems/${err.code}`, title: err.title, status: err.status, code: err.code, detail: err.message });
  res.writeHead(err.status, { ...SECURITY_HEADERS, ...headers, "content-type": "application/problem+json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

export async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new AuthError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new AuthError(400, "invalid-json", "The body must be a JSON object.");
  }
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of header?.split(";") ?? []) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function cookie(name: string, value: string, opts: { secure: boolean; maxAge?: number; path?: string; sameSite?: "Lax" | "Strict" }) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path ?? "/"}`, "HttpOnly", `SameSite=${opts.sameSite ?? "Lax"}`];
  if (opts.secure) parts.push("Secure");
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  return parts.join("; ");
}

// Field checks for request bodies. Each throws a 422 that names the field.
export function str(body: Record<string, unknown>, name: string, opts: { min?: number; max?: number; optional?: false }): string;
export function str(body: Record<string, unknown>, name: string, opts: { min?: number; max?: number; optional: true }): string | undefined;
export function str(body: Record<string, unknown>, name: string, { min = 1, max = 256, optional = false }: { min?: number; max?: number; optional?: boolean }) {
  const v = body[name];
  if (v === undefined && optional) return undefined;
  if (typeof v !== "string" || v.length < min || v.length > max) throw new AuthError(422, "invalid-body", `${name} must be a string of ${min} to ${max} characters.`);
  return v;
}

export function email(body: Record<string, unknown>): string {
  const v = str(body, "email", { max: 254 }).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+$/.test(v)) throw new AuthError(422, "invalid-body", "email must be an email address.");
  return v;
}

export const clientIp = (req: IncomingMessage) => req.socket.remoteAddress ?? "unknown";
