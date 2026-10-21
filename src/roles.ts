// Per-product roles (ADR 0003), lowest first. Each role can do everything the ones before it can. "user" is for
// products whose members include people who use them without managing them, such as Identity's directory: it is only
// accepted where the product turns it on (`users`), and gives no access to the product's own API.
export const ROLES = ["user", "viewer", "editor", "admin", "owner"] as const;
export type Role = (typeof ROLES)[number];

export const isRole = (v: unknown): v is Role => typeof v === "string" && (ROLES as readonly string[]).includes(v);
export const atLeast = (role: Role, min: Role) => ROLES.indexOf(role) >= ROLES.indexOf(min);
/** The highest of these roles, or undefined for none. */
export const highest = (roles: Role[]) => roles.reduce<Role | undefined>((a, b) => (!a || atLeast(b, a) ? b : a), undefined);
/** Owners and admins must use a second factor (ADR 0002). */
export const needsMfa = (role: Role) => atLeast(role, "admin");
