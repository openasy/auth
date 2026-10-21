import type { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones. The tables live in the
// product's own SQLite file (ADR 0011) with an `auth_` prefix and their own migration table, so they never clash
// with the product's migrations.
interface Migration {
  sql: string;
  /**
   * Rebuilds a table other tables point at: foreign keys are off while it runs, so dropping the old table does not
   * delete what points at it, and checked before it commits (https://sqlite.org/lang_altertable.html#otheralter).
   */
  rebuild?: boolean;
}

const MIGRATIONS: Array<string | Migration> = [
  `-- People who can sign in to this product. role is per product (ADR 0003).
   CREATE TABLE auth_users (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL UNIQUE COLLATE NOCASE,
     name TEXT NOT NULL,
     role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer')),
     status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
     password_hash TEXT,
     created_at TEXT NOT NULL,
     last_sign_in_at TEXT
   );
   -- Accounts at an identity provider (OIDC today) that sign in as a user.
   CREATE TABLE auth_identities (
     provider TEXT NOT NULL,
     subject TEXT NOT NULL,
     user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
     email TEXT,
     created_at TEXT NOT NULL,
     last_used_at TEXT,
     PRIMARY KEY (provider, subject)
   );
   CREATE INDEX auth_identities_user ON auth_identities (user_id);
   -- Only the SHA-256 of a session id is stored; the id itself lives in the browser's cookie.
   CREATE TABLE auth_sessions (
     id_hash TEXT PRIMARY KEY,
     id TEXT NOT NULL UNIQUE,
     user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
     method TEXT NOT NULL,
     mfa INTEGER NOT NULL DEFAULT 0,
     ip TEXT,
     user_agent TEXT,
     created_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     expires_at TEXT NOT NULL
   );
   CREATE INDEX auth_sessions_user ON auth_sessions (user_id);
   CREATE TABLE auth_totp (
     user_id TEXT PRIMARY KEY REFERENCES auth_users (id) ON DELETE CASCADE,
     secret TEXT NOT NULL,
     confirmed INTEGER NOT NULL DEFAULT 0,
     -- The last 30-second step a code was accepted for, so a code cannot be used twice.
     last_step INTEGER NOT NULL DEFAULT 0,
     created_at TEXT NOT NULL
   );
   CREATE TABLE auth_passkeys (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     public_key BLOB NOT NULL,
     counter INTEGER NOT NULL,
     transports TEXT NOT NULL DEFAULT '[]',
     created_at TEXT NOT NULL,
     last_used_at TEXT
   );
   CREATE INDEX auth_passkeys_user ON auth_passkeys (user_id);
   CREATE TABLE auth_recovery_codes (
     user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
     code_hash TEXT NOT NULL,
     used_at TEXT,
     PRIMARY KEY (user_id, code_hash)
   );
   -- Short-lived state between two requests: a sign-in waiting for its second factor, a WebAuthn challenge, an
   -- OIDC redirect, an invitation or the first-start setup link. Only the hash of the id is stored.
   CREATE TABLE auth_challenges (
     id_hash TEXT PRIMARY KEY,
     kind TEXT NOT NULL,
     user_id TEXT REFERENCES auth_users (id) ON DELETE CASCADE,
     data TEXT NOT NULL DEFAULT '{}',
     expires_at TEXT NOT NULL
   );
   -- API tokens (ADR 0003): one product, one role at most the creator's, always an expiry.
   CREATE TABLE auth_tokens (
     id TEXT PRIMARY KEY,
     secret_hash TEXT NOT NULL UNIQUE,
     name TEXT NOT NULL,
     role TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
     created_by TEXT REFERENCES auth_users (id) ON DELETE SET NULL,
     created_at TEXT NOT NULL,
     expires_at TEXT NOT NULL,
     last_used_at TEXT
   )`,
  `-- The browser and operating system a session was opened on, without version numbers (see deviceOf).
   ALTER TABLE auth_sessions ADD COLUMN device TEXT NOT NULL DEFAULT ''`,
  `-- Identity providers added under Settings, Sign-in (ADR 0033), next to the ones from the environment. The client
   -- secret is sealed with the secrets key; lists are JSON.
   CREATE TABLE auth_providers (
     id TEXT PRIMARY KEY,
     preset TEXT NOT NULL,
     name TEXT NOT NULL,
     issuer TEXT NOT NULL,
     client_id TEXT NOT NULL,
     client_secret TEXT,
     scopes TEXT NOT NULL,
     groups_claim TEXT,
     role_mapping TEXT NOT NULL DEFAULT '{}',
     default_role TEXT CHECK (default_role IN ('owner', 'admin', 'editor', 'viewer')),
     allowed_domains TEXT NOT NULL DEFAULT '[]',
     enabled INTEGER NOT NULL DEFAULT 1,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   )`,
  {
    // 0.3.0: the user role, for products whose members include people who only use them (ADR 0033).
    rebuild: true,
    sql: `CREATE TABLE auth_users_new (
       id TEXT PRIMARY KEY,
       email TEXT NOT NULL UNIQUE COLLATE NOCASE,
       name TEXT NOT NULL,
       role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer', 'user')),
       status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
       password_hash TEXT,
       created_at TEXT NOT NULL,
       last_sign_in_at TEXT
     );
     INSERT INTO auth_users_new SELECT id, email, name, role, status, password_hash, created_at, last_sign_in_at FROM auth_users;
     DROP TABLE auth_users;
     ALTER TABLE auth_users_new RENAME TO auth_users;
     ALTER TABLE auth_providers RENAME COLUMN default_role TO default_role_old;
     ALTER TABLE auth_providers ADD COLUMN default_role TEXT CHECK (default_role IN ('owner', 'admin', 'editor', 'viewer', 'user'));
     UPDATE auth_providers SET default_role = default_role_old;
     ALTER TABLE auth_providers DROP COLUMN default_role_old`,
  },
  `-- 0.4.0: which second factor opened a session (totp, passkey or recovery-code), for products that ask for a passkey.
   ALTER TABLE auth_sessions ADD COLUMN factor TEXT`,
];

/** Migrates forward; `until` stops after that many migrations, for tests of upgrades. */
export function migrate(db: DatabaseSync, until = MIGRATIONS.length) {
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("CREATE TABLE IF NOT EXISTS auth_schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM auth_schema_migrations").get() as { v: number };
  for (let v = row.v; v < until; v++) {
    const m = MIGRATIONS[v]!;
    const { sql, rebuild = false } = typeof m === "string" ? { sql: m } : m;
    // PRAGMA foreign_keys has no effect inside a transaction, so it is switched around it.
    if (rebuild) db.exec("PRAGMA foreign_keys = OFF");
    db.exec("BEGIN");
    try {
      db.exec(sql);
      if (rebuild) {
        const broken = db.prepare("PRAGMA foreign_key_check").all();
        if (broken.length) throw new Error(`auth migration ${v + 1} would break ${broken.length} references`);
      }
      db.prepare("INSERT INTO auth_schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    } finally {
      if (rebuild) db.exec("PRAGMA foreign_keys = ON");
    }
  }
}
