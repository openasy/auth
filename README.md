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
| Roles | Owner, Admin, Editor, Viewer, per product. At least one owner always remains. With `users: true`, also User: people who use the product's applications, such as Identity's, without managing it |
| API tokens | One product, one role (at most the creator's), always an expiry, shown once, only the hash is stored |
| CSRF | Unsafe requests with the session cookie must come from the product's origin |

SAML 2.0, LDAP, trusted proxy headers and GitHub sign-in are planned (see ADR 0002).

## Install

Each release attaches the built package to its [GitHub release](https://github.com/openasy/auth/releases); no registry or token is needed.

```bash
npm install https://github.com/openasy/auth/releases/download/v0.9.0/openasy-auth-0.9.0.tgz
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

### Identity providers

`PRESETS` (also at `@openasy/auth/presets`, without Node imports, for screens) holds the name, scopes, groups claim
and setup steps for Keycloak, Microsoft Entra ID, Okta, Google, authentik, ZITADEL and OpenAsy Identity. In the
environment, `OPENASY_OIDC_PROVIDER=keycloak` makes them the defaults; the other variables still win.

- **Groups** are read from the ID token, or from userinfo when the token has none. `groupsClaim` is a claim name or a
  dotted path into nested claims: `realm_access.roles` for Keycloak realm roles. A list, one name, or an object whose
  keys are the names (ZITADEL's `urn:zitadel:iam:org:project:roles`) all work.
- **Settings, Sign-in:** owners add providers under `/providers` as well as in the environment. The client secret is
  sealed with the secrets key and never returned. Removing a provider, or pointing it at another issuer, unlinks the
  people who signed in through it, so another provider's account with the same subject is never taken for theirs.
  `allowInsecureIssuers` allows http:// issuers there, for tests and local providers only.
- **A ready Keycloak:** [`examples/keycloak`](./examples/keycloak) starts Keycloak with a realm in which every OpenAsy
  product is a client, with groups and a groups claim. CI signs in through it on every change.
- **Passwords another directory keeps:** `externalPasswords: { managedBy, verify }` lets a product say whose password
  lives elsewhere, such as Active Directory: it is checked there at sign-in, and they cannot set one here.
- **Which second factor:** a session knows whether it was opened with a code, a passkey or a recovery code
  (`factor`), so a product can ask for a passkey.
- **Groups for the product:** `onOidcSignIn({ userId, provider, groups })` runs after each sign-in through a
  provider, so a product can keep the groups; Identity does.
- **Straight to the provider:** `autoRedirect` on a provider, `OPENASY_OIDC_AUTO_REDIRECT=true` in the environment
  or the switch under Settings, Sign-in, makes the sign-in screen
  open that provider instead of the product's form. With a session there already, people land in the product without
  seeing a screen. It does not happen after signing out, after a failed sign-in, or with `?local=1` in the address,
  which is how an owner signs in while the provider is down. At most one provider has it.
- **Too many groups:** Microsoft Entra ID leaves the groups out of a token when there are too many. With a role
  mapping, the person is refused with what to change, rather than given the wrong role.

The OpenAPI description of the routes is `authOpenApi()`; serve `mergeOpenApi(yourSpec)` so your API reference includes
sign-in. `test/contract.test.ts` checks every response against it. Each product reads the secrets key with
`readSecretsKey(path)` and one OIDC provider from its environment with `oidcFromEnv(process.env, "VULNS_")`. The
variables have the same names in every product, like `OPENASY_PRODUCTS`, so an install sets them once; only the
client differs, because each product is its own application at the provider:

| Variable | |
| --- | --- |
| `OPENASY_OIDC_ISSUER`, `OPENASY_OIDC_CLIENT_ID`, `OPENASY_OIDC_CLIENT_SECRET` | Required to turn it on. The client is this product's |
| `OPENASY_OIDC_PROVIDER` | `keycloak`, `entra`, `okta`, `google`, `authentik`, `zitadel` or `openasy-identity`: that provider's defaults |
| `OPENASY_OIDC_NAME` | On the button: "Continue with ...". Default `SSO` |
| `OPENASY_OIDC_SCOPES` | Default `openid email profile`; add the scope that carries groups |
| `OPENASY_OIDC_GROUPS_CLAIM` | Default `groups`; a dotted path such as `realm_access.roles` reads nested claims |
| `OPENASY_OIDC_ROLE_MAPPING` | `openasy-admins=admin,staff=viewer`: the role follows the groups on every sign-in |
| `OPENASY_OIDC_DEFAULT_ROLE` | Role for people nobody invited. Unset: only invited people and mapped groups get in |
| `OPENASY_OIDC_ALLOWED_DOMAINS` | Comma-separated email domains, for providers anyone can join (Google) |
| `OPENASY_OIDC_AUTO_REDIRECT` | `true`: the sign-in page opens the provider straight away |

Before 0.5.0 the names had the product's prefix (`VULNS_OIDC_ISSUER`). The second argument still reads those when the
shared name is unset, with a deprecation warning; a later release drops them.

```tsx
import { AuthGate, AccountSettings, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";

<BrandProvider brand={{ name: "OpenAsy" }} locale={locale}>
  <AuthGate product="OpenAsy Vulnerabilities">
    <Product /> {/* useAuth(): me, can("editor"), signOut(), expired() */}
  </AuthGate>
</BrandProvider>;
```

**The install's brand (ADR 0053):** `OPENASY_ORGANIZATION`, `OPENASY_ACCENT` (`#rrggbb`), `OPENASY_LOGO`, the path
of a mounted SVG, PNG or WebP file up to 512 KB in any shape, and `OPENASY_FAVICON`, a square SVG, PNG or ICO up to
128 KB, are read at start. `GET /methods` sends them and the pictures are served from `GET /brand/logo` and
`GET /brand/favicon`, an SVG in a sandbox. A wrong value is left out with a warning in the log. In the web UI,
`useInstallBrand()` returns them for `BrandProvider` and makes the favicon the tab's icon:
`brand={{ name: "OpenAsy", ...useInstallBrand() }}`. A logo stands for the brand: the sign-in screen shows it at a
fixed height, without the brand's name.

Settings pages: `AccountSettings` for everyone, `MembersSettings` and `TokensSettings` for admins, and
`SignInSettings` for identity providers: admins see them, owners add them from a preset with that provider's steps and
redirect URI, check the issuer and map groups to roles. With a provider set up, the first-start setup page also offers
to become the owner through it.

**With Identity (ADR 0033):** when the provider is `openasy-identity`, Identity keeps the people who sign in through
it, and `GET /me` names it in `managedBy`. `AccountSettings` and `MembersSettings` send the browser to Identity's
Account and People pages. `AuthGate` keeps the theme and language of the browser the person's own: it reads them from
Identity's `GET /me/preferences` when the page opens and whenever the person comes back to it, and sends a choice made
in the product there, so a change made in one product or in Identity shows in all of them. The name shown is Identity's
too. Without Identity, they are kept by the product itself, so they follow the person from browser to browser. Identity
passes `preferenceOrigins`, the origins of its applications, so their pages may call it with its session cookie; this
works when the products share a site, such as `id.example.com` and `vpn.example.com`, and with Identity set in the
environment. The product's content security policy names it in `connect-src`: `identityOrigin(process.env)` returns
its origin.

The screens speak English, Turkish and German, in the `locale` given to `BrandProvider` (`useLocalePreference()` from
`@openasy/ui` 0.6.0 or later). Their words are in `src/messages/en.json`, `tr.json` and `de.json`, in i18next's `auth`
namespace. Messages from the server and each provider's setup
steps are still in English.

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
| `GET /methods` | anyone: password on or off, OIDC providers, whether setup is needed, the brand |
| `GET /brand/logo` | anyone: the logo from `OPENASY_LOGO` |
| `GET /brand/favicon` | anyone: the tab icon from `OPENASY_FAVICON` |
| `POST /setup` | the holder of the first-start link |
| `POST /login`, `POST /login/mfa`, `POST /login/passkey/options`, `POST /login/passkey` | anyone |
| `GET /oidc/:id/start`, `GET /oidc/:id/callback` | anyone |
| `POST /logout` | signed in |
| `GET`, `POST /links/:token` | the holder of an invitation or password link |
| `GET`, `PATCH /me`, `POST /me/password`, `GET /me/sessions`, `DELETE /me/sessions/:id` | signed in |
| `GET`, `PATCH /me/preferences` | signed in, also from the pages of `preferenceOrigins` |
| `POST /me/totp`, `POST /me/totp/confirm`, `DELETE /me/totp`, `POST /me/recovery-codes` | signed in |
| `POST /me/passkeys/options`, `POST /me/passkeys`, `DELETE /me/passkeys/:id` | signed in |
| `GET`, `POST /members`, `PATCH`, `DELETE /members/:id`, `POST /members/:id/reset` | admin (owners for owners) |
| `GET`, `POST /tokens`, `DELETE /tokens/:id` | admin |
| `GET /providers` | admin: identity providers from the environment and from Settings, never their secrets |
| `POST /providers`, `PATCH`, `DELETE /providers/:id`, `POST /providers/discover` | owner: a role mapping can make anyone in a group an owner |

## Not built yet

- Email: invitations and password resets are links an admin passes on.
- Binding sessions to a key held by the device (Device Bound Session Credentials), once browsers support it widely.
- Custom roles from named permissions (ADR 0003).

## Licence

Apache-2.0, like `@openasy/ui`, so anyone can build on it. The products that use it are AGPL-3.0 (ADR 0008).
