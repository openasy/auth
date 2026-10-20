# @openasy/auth

Sign-in shared by every [OpenAsy](https://github.com/openasy) product, so each one signs people in the same way and
no product writes its own password, session or MFA code ([ADR 0002](https://github.com/openasy/openasy.github.io/blob/main/docs/decisions/0002-authentication.md),
[ADR 0003](https://github.com/openasy/openasy.github.io/blob/main/docs/decisions/0003-authorization.md)).

Each product embeds it and keeps its own users in its own SQLite file, so a product still runs alone (ADR 0001).

| | |
| --- | --- |
| Local accounts | Argon2id (Node's built-in `crypto.argon2`), 12 characters minimum, throttled after 10 failures |
| Second factors | Authenticator apps (TOTP, RFC 6238, codes used once), passkeys (WebAuthn), ten single-use recovery codes. Required for owners and admins who sign in with a password |
| Passkeys alone | Sign in with only a passkey when the device verified the person (biometrics or PIN) |
| OIDC | Any OpenID Connect provider (Entra ID, Okta, Google, Keycloak, Authentik, Zitadel, OpenAsy Identity). Code flow with PKCE, state and nonce; groups mapped to roles on every sign-in |
| Sessions | Opaque id in an `HttpOnly`, `SameSite=Lax`, `__Host-` cookie; only its hash is stored. 60 minutes idle, 12 hours at most, listed and revocable. Bound to the browser and operating system: a copied cookie used elsewhere ends the session |
| Roles | Owner, Admin, Editor, Viewer, per product. At least one owner always remains |
| API tokens | One product, one role (at most the creator's), always an expiry, shown once, only the hash is stored |
| CSRF | Unsafe requests with the session cookie must come from the product's origin |

SAML 2.0, LDAP, trusted proxy headers and GitHub sign-in are planned (see ADR 0002).

## Install

Each release attaches the built package to its [GitHub release](https://github.com/openasy/auth/releases); no registry or token is needed.

```bash
npm install https://github.com/openasy/auth/releases/download/v0.1.0/openasy-auth-0.1.0.tgz
```

Node 26 or later.

## Use it in a product

```ts
import { createAuth, AuthError, sendProblem } from "@openasy/auth";

const auth = createAuth({
  db, // the product's DatabaseSync; tables are added with an auth_ prefix
  product: "vulns",
  productName: "OpenAsy Vulnerabilities",
  origin: "https://vulns.example.com",
  secretsKey, // 32 bytes from a mounted secret (ADR 0021); TOTP secrets are encrypted with it
  oidc: [{ id: "corp", name: "Corp SSO", issuer: "https://login.example.com", clientId: "vulns", clientSecret, roleMapping: { "vulns-admins": "admin" } }],
  onEvent: (e) => log("info", "auth", e), // audit log (ADR 0013)
});

createServer(async (req, res) => {
  if (await auth.handle(req, res)) return; // everything under /api/v1/auth
  try {
    const who = auth.authorize(req, "editor"); // 401 or 403 as AuthError
  } catch (err) {
    if (err instanceof AuthError) return sendProblem(res, err);
    throw err;
  }
});

const link = auth.setupLink(); // print on first start: creates the owner (ADR 0013)
setInterval(() => auth.purge(), 5 * 60_000);
```

The OIDC redirect URI to register at the provider is `<origin>/api/v1/auth/oidc/<id>/callback`.

The OpenAPI description of the routes is `authOpenApi()`; serve `mergeOpenApi(yourSpec)` so your API reference includes
sign-in. `test/contract.test.ts` checks every response against it. Each product can read one OIDC provider from its
environment with `oidcFromEnv(process.env, "VULNS_")` and the secrets key with `readSecretsKey(path)`.

```tsx
import { AuthGate, AccountSettings, MembersSettings, TokensSettings, useAuth } from "@openasy/auth/react";

<BrandProvider brand={{ name: "OpenAsy" }}>
  <AuthGate product="OpenAsy Vulnerabilities">
    <Product /> {/* useAuth(): me, can("editor"), signOut(), expired() */}
  </AuthGate>
</BrandProvider>;
```

In the web UI, `@openasy/auth/client` calls the same routes, including the browser's passkey prompts:

```ts
import { auth, takeAuthParams } from "@openasy/auth/client";

const { setup, link, error } = takeAuthParams(); // one-time tokens from ?setup= and ?link=
const methods = await auth.methods();
const result = await auth.signIn(email, password); // { status: "mfa-required" } → auth.verifyCode(code)
```

The screens themselves are in [`@openasy/ui`](https://github.com/openasy/ui).

## Routes

All under `/api/v1/auth`. Errors are RFC 9457 problems with a stable `code`.

| Route | Who |
| --- | --- |
| `GET /methods` | anyone: password on or off, OIDC providers, whether setup is needed |
| `POST /setup` | the holder of the first-start link |
| `POST /login`, `POST /login/mfa`, `POST /login/passkey/options`, `POST /login/passkey` | anyone |
| `GET /oidc/:id/start`, `GET /oidc/:id/callback` | anyone |
| `POST /logout` | signed in |
| `GET`, `POST /links/:token` | the holder of an invitation or password link |
| `GET`, `PATCH /me`, `POST /me/password`, `GET /me/sessions`, `DELETE /me/sessions/:id` | signed in |
| `POST /me/totp`, `POST /me/totp/confirm`, `DELETE /me/totp`, `POST /me/recovery-codes` | signed in |
| `POST /me/passkeys/options`, `POST /me/passkeys`, `DELETE /me/passkeys/:id` | signed in |
| `GET`, `POST /members`, `PATCH`, `DELETE /members/:id`, `POST /members/:id/reset` | admin (owners for owners) |
| `GET`, `POST /tokens`, `DELETE /tokens/:id` | admin |

## Not built yet

- Email: invitations and password resets are links an admin passes on.
- Binding sessions to a key held by the device (Device Bound Session Credentials), once browsers support it widely.
- Custom roles from named permissions (ADR 0003).

## Licence

Apache-2.0, like `@openasy/ui`, so anyone can build on it. The products that use it are AGPL-3.0 (ADR 0008).
