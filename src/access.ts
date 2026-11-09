// Who may do what in each product, from one file every product reads (ADR 0003, 0074). An install keeps it in
// inventory/access.yaml next to the hosts and endpoints files (ADR 0052), names it in OPENASY_ACCESS, and reviews a
// change to it like code. While it is in use, it is the only way a person gets a role: Settings, Members shows the
// roles and no longer changes them.
//
//   access:
//     - group: openasy-admins     # a group as the sign-in provider sends it, or
//       products: "*"             # every product, or a list of product ids
//       role: admin
//     - person: ayse@example.com  # one person by their email address
//       products: [infra, logs]
//       role: owner
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { parse } from "yaml";
import { atLeast, isRole, type Role } from "./roles.ts";

export interface AccessRule {
  /** Its place in the file, from 1, so a role can say where it comes from. */
  n: number;
  group: string | null;
  person: string | null;
  products: "*" | string[];
  role: Role;
}

export interface AccessGrant {
  role: Role;
  /** The rule that gives it, as the file has it: "rule 2: group ops". */
  rule: string;
}

export interface AccessFileState {
  path: string;
  /** When a version of the file was last applied; null until one is. */
  appliedAt: string | null;
  rules: number;
  /** Why the file as it is now is not applied; its last good version still is. */
  error: string | null;
}

const PRODUCT = /^[a-z][a-z0-9-]{0,31}$/;
const GROUP = /^[^\s,=][^,=]{0,255}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const KEYS = new Set(["group", "person", "products", "role", "where"]);

/** Where a rule comes from, for Members and the audit log. */
export const ruleLabel = (r: AccessRule) => `rule ${r.n}: ${r.group !== null ? `group ${r.group}` : `person ${r.person}`}`;

const applies = (r: AccessRule, product: string) => r.products === "*" || r.products.includes(product);

/**
 * Reads the file's text. Throws with the rule and field to fix. The whole file is checked, not only the rules for
 * `product`, so every product refuses the same mistake. `product` must have at least one owner.
 */
export function parseAccess(text: string, product: string): AccessRule[] {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    throw new Error(`Not YAML: ${(err as Error).message.split("\n")[0]}`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray((doc as { access?: unknown }).access))
    throw new Error("The file must have an access: list.");
  const other = Object.keys(doc).filter((k) => k !== "access");
  if (other.length) throw new Error(`Unknown top-level field: ${other.join(", ")}. The file has only access:.`);
  const rules = (doc as { access: unknown[] }).access.map((raw, i): AccessRule => {
    const n = i + 1;
    const bad = (m: string) => new Error(`Rule ${n}: ${m}`);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw bad("must be a map with group or person, products and role.");
    const e = raw as Record<string, unknown>;
    const unknown = Object.keys(e).filter((k) => !KEYS.has(k));
    if (unknown.length) throw bad(`unknown field ${unknown.join(", ")}.`);
    if ((e.group === undefined) === (e.person === undefined)) throw bad("give either group or person.");
    if (e.group !== undefined && (typeof e.group !== "string" || !GROUP.test(e.group.trim()))) throw bad("group must be a group's name, without commas or =.");
    if (e.person !== undefined && (typeof e.person !== "string" || !EMAIL.test(e.person.trim()))) throw bad("person must be an email address.");
    let products: AccessRule["products"];
    if (e.products === "*") products = "*";
    else if (Array.isArray(e.products) && e.products.length && e.products.every((p) => typeof p === "string" && PRODUCT.test(p)))
      products = e.products as string[];
    else throw bad('products must be "*" or a list of product ids, such as [infra, logs].');
    if (!isRole(e.role)) throw bad("role must be owner, admin, editor, viewer or user.");
    // Scoping a rule to tagged hosts or endpoints comes in a later version; until then, refuse it rather than give
    // more than the rule says.
    if (e.where !== undefined) throw bad("where is not supported yet: give the role for the whole product.");
    return {
      n,
      group: typeof e.group === "string" ? e.group.trim() : null,
      person: typeof e.person === "string" ? e.person.trim().toLowerCase() : null,
      products,
      role: e.role,
    };
  });
  if (!rules.some((r) => r.role === "owner" && applies(r, product)))
    throw new Error(`No rule makes anyone an owner of ${product}: add one, such as products: "*" with role: owner.`);
  return rules;
}

/**
 * The highest role the rules give this person in `product`, and the rule that gives it, or undefined for none. The
 * user role counts only where the product has users (`users`).
 */
export function grantFor(rules: AccessRule[], product: string, email: string, groups: Iterable<string>, users = false): AccessGrant | undefined {
  const mine = new Set(groups);
  const who = email.toLowerCase();
  let best: AccessRule | undefined;
  for (const r of rules) {
    if (!applies(r, product) || (r.role === "user" && !users)) continue;
    if (r.person !== null ? r.person !== who : !mine.has(r.group!)) continue;
    if (!best || (r.role !== best.role && atLeast(r.role, best.role))) best = r;
  }
  return best && { role: best.role, rule: ruleLabel(best) };
}

/** The access file's path from the environment, the same variable in every product. */
export const accessFromEnv = (env: Record<string, string | undefined>) => env.OPENASY_ACCESS?.trim() || undefined;

/**
 * Reads the file now and whenever it changes (checked every `everyMs`, by size, time and content), and hands each
 * good version to `apply`. A file that cannot be read or has a mistake leaves the last good version in place.
 */
export function watchAccess(
  path: string,
  product: string,
  apply: (rules: AccessRule[]) => void,
  { everyMs = 60_000, onChange }: { everyMs?: number; onChange?: (state: AccessFileState) => void } = {},
) {
  const state: AccessFileState = { path, appliedAt: null, rules: 0, error: null };
  let seen = "";
  const read = () => {
    let text: string;
    let stamp: string;
    try {
      const st = statSync(path);
      text = readFileSync(path, "utf8");
      stamp = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(text).digest("hex")}`;
    } catch (err) {
      const error = `Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;
      if (state.error !== error) ((state.error = error), onChange?.(state));
      return;
    }
    if (stamp === seen) return;
    seen = stamp;
    try {
      const rules = parseAccess(text, product);
      apply(rules);
      Object.assign(state, { appliedAt: new Date().toISOString(), rules: rules.length, error: null });
    } catch (err) {
      state.error = (err as Error).message;
    }
    onChange?.(state);
  };
  read();
  const timer = setInterval(read, everyMs);
  timer.unref();
  return { state, read, stop: () => clearInterval(timer) };
}
