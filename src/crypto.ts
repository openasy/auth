import { argon2, createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const argon2Async = promisify(argon2);

/** A random id or secret, base64url. 32 bytes is 256 bits. */
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (value: string) => createHash("sha256").update(value).digest("base64url");

// Argon2id with the OWASP minimum (19 MiB, 2 passes, 1 lane). Stored in the PHC string format so the parameters can
// be raised later and old hashes still verify.
const ARGON = { memory: 19_456, passes: 2, parallelism: 1, tagLength: 32 };

export async function hashPassword(password: string): Promise<string> {
  const nonce = randomBytes(16);
  const tag = await argon2Async("argon2id", { message: password, nonce, ...ARGON });
  return `$argon2id$v=19$m=${ARGON.memory},t=${ARGON.passes},p=${ARGON.parallelism}$${nonce.toString("base64url")}$${tag.toString("base64url")}`;
}

export async function verifyPassword(password: string, phc: string): Promise<boolean> {
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([\w-]+)\$([\w-]+)$/.exec(phc);
  if (!m) return false;
  const expected = Buffer.from(m[5]!, "base64url");
  const tag = await argon2Async("argon2id", {
    message: password,
    nonce: Buffer.from(m[4]!, "base64url"),
    memory: Number(m[1]),
    passes: Number(m[2]),
    parallelism: Number(m[3]),
    tagLength: expected.length,
  });
  return timingSafeEqual(tag, expected);
}

/** Hashed when the email is unknown, so a wrong email takes as long as a wrong password. */
export const DUMMY_HASH = await hashPassword(randomToken());

// TOTP (RFC 6238): SHA-1, 6 digits, 30 seconds, as every authenticator app supports.
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function fromBase32(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const i = BASE32.indexOf(ch);
    if (i < 0) throw new Error("invalid base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const TOTP_STEP = 30;

export function totp(secret: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac[mac.length - 1]! & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** The step the code matches, allowing one step of clock drift either way, or null. */
export function matchTotp(secret: Buffer, code: string, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(now / 1000 / TOTP_STEP);
  for (const step of [current, current - 1, current + 1]) {
    if (timingSafeEqual(Buffer.from(totp(secret, step)), Buffer.from(code))) return step;
  }
  return null;
}

/** Ten single-use codes like `k7m2q-x9d4p`, for when the authenticator is lost. */
export function recoveryCodes(): string[] {
  return Array.from({ length: 10 }, () => {
    const s = base32(randomBytes(7)).toLowerCase().slice(0, 10);
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
}
export const normalizeRecoveryCode = (code: string) => code.toLowerCase().replace(/[^a-z2-7]/g, "");

/**
 * Encrypts secrets kept in the database (TOTP secrets) with AES-256-GCM when the product gives a key (ADR 0021).
 * Without a key they are stored as `plain:` and the product should warn.
 */
export function sealer(key?: Buffer) {
  if (key && key.length !== 32) throw new Error("secretsKey must be 32 bytes");
  return {
    seal(plain: string): string {
      if (!key) return `plain:${plain}`;
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
      return `v1:${Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64url")}`;
    },
    open(sealed: string): string {
      if (sealed.startsWith("plain:")) return sealed.slice(6);
      if (!key) throw new Error("this secret is encrypted; set the secrets key");
      const raw = Buffer.from(sealed.slice(3), "base64url");
      const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
      decipher.setAuthTag(raw.subarray(12, 28));
      return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
    },
  };
}
