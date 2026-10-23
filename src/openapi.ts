// The OpenAPI description of /api/v1/auth (ADR 0014, 0024). Products merge it into their own description with
// `mergeOpenApi`, so their API reference documents sign-in too; test/contract.test.ts checks every response against it.

type Schema = Record<string, unknown>;
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const str = { type: "string" };
const dateTime = { type: "string", format: "date-time" };
const nullable = (s: Schema) => ({ anyOf: [s, { type: "null" }] });
const obj = (properties: Record<string, Schema>, required = Object.keys(properties)) => ({ type: "object", required, properties });
const role = {
  type: "string",
  enum: ["owner", "admin", "editor", "viewer", "user"],
  description: "user only in products that turn it on: people who use the product's applications without managing it.",
};
const tokenRole = { type: "string", enum: ["admin", "editor", "viewer"] };

const schemas: Record<string, Schema> = {
  AuthProblem: obj(
    {
      type: { type: "string", format: "uri" },
      title: str,
      status: { type: "integer" },
      code: {
        type: "string",
        description: "Stable; match on this.",
        enum: [
          "unauthenticated",
          "invalid-credentials",
          "invalid-token",
          "mfa-required",
          "mfa-setup-required",
          "forbidden",
          "cross-site",
          "invalid-json",
          "invalid-body",
          "not-found",
          "conflict",
          "rate-limited",
          "not-configured",
        ],
      },
      detail: str,
    },
    ["type", "title", "status", "code"],
  ),
  AuthMethods: obj({
    passwords: { type: "boolean" },
    passkeys: { type: "boolean" },
    users: { type: "boolean", description: "Members may have the user role." },
    providers: { type: "array", items: obj({ id: str, name: str }) },
    autoRedirect: nullable({ type: "string", description: "The provider the sign-in screen goes straight to, or null to show the screen." }),
    setupRequired: { type: "boolean", description: "No owner yet: open the setup link from the log." },
    brand: obj({
      organization: nullable({ type: "string", description: "Shown under the product's name (OPENASY_ORGANIZATION)." }),
      accent: nullable({ type: "string", pattern: "^#[0-9a-f]{6}$", description: "Buttons and links (OPENASY_ACCENT)." }),
      logo: nullable({ type: "string", description: "The logo's path on this product, which changes with the picture (OPENASY_LOGO)." }),
      favicon: nullable({ type: "string", description: "The tab icon's path on this product, which changes with the picture (OPENASY_FAVICON)." }),
    }),
  }),
  AuthMember: obj({
    id: str,
    email: str,
    name: str,
    role,
    status: { type: "string", enum: ["invited", "active", "disabled"] },
    createdAt: dateTime,
    lastSignInAt: nullable(dateTime),
    mfa: obj({ totp: { type: "boolean" }, passkeys: { type: "integer" } }),
    providers: { type: "array", items: str, description: "Identity providers this person has signed in with." },
  }),
  AuthSignedIn: obj({ status: { const: "signed-in" }, user: ref("AuthMember"), mfaSetupRequired: { type: "boolean" } }),
  AuthMfaRequired: obj({
    status: { const: "mfa-required" },
    methods: { type: "array", items: { type: "string", enum: ["totp", "passkey", "recovery-code"] } },
  }),
  AuthMe: obj({
    user: ref("AuthMember"),
    session: obj({
      id: str,
      method: str,
      mfa: { type: "boolean" },
      factor: nullable({
        type: "string",
        enum: ["totp", "passkey", "recovery-code"],
        description: "The second factor the session was opened with, or added during it.",
      }),
    }),
    passwordManagedBy: nullable({
      type: "string",
      description: "The directory that keeps this person's password, such as Active Directory; they change it there.",
    }),
    mfaSetupRequired: { type: "boolean" },
    hasPassword: { type: "boolean" },
    passkeys: { type: "array", items: obj({ id: str, name: str, createdAt: dateTime, lastUsedAt: nullable(dateTime) }) },
    recoveryCodesLeft: { type: "integer" },
  }),
  AuthSession: obj({ id: str, method: str, ip: str, userAgent: str, createdAt: dateTime, lastSeenAt: dateTime, current: { type: "boolean" } }),
  AuthRecoveryCodes: obj({ recoveryCodes: { type: "array", items: str, minItems: 10, maxItems: 10 } }),
  AuthLink: obj({ link: { type: "string", format: "uri" }, linkExpiresAt: dateTime }),
  AuthResetLink: obj({
    link: nullable({
      type: "string",
      format: "uri",
      description: "null for someone whose password another directory keeps: only their second factors were reset.",
    }),
    linkExpiresAt: nullable(dateTime),
  }),
  AuthToken: obj({
    id: str,
    name: str,
    role: tokenRole,
    createdBy: nullable(str),
    createdAt: dateTime,
    expiresAt: dateTime,
    lastUsedAt: nullable(dateTime),
    expired: { type: "boolean" },
  }),
  AuthProvider: obj({
    id: str,
    name: str,
    preset: { type: "string", description: "Which settings it started from: keycloak, entra, okta, google, authentik, zitadel, openasy-identity or generic." },
    source: { type: "string", enum: ["settings", "environment"], description: "Providers from the environment are changed there, not here." },
    enabled: { type: "boolean" },
    issuer: str,
    clientId: str,
    hasClientSecret: { type: "boolean", description: "The secret itself is never returned." },
    scopes: { type: "array", items: str },
    groupsClaim: nullable(str),
    roleMapping: { type: "object", additionalProperties: role },
    defaultRole: nullable(role),
    allowedDomains: { type: "array", items: str },
    autoRedirect: { type: "boolean", description: "The sign-in screen goes straight to this provider. At most one has it." },
    redirectUri: { type: "string", format: "uri", description: "Register this at the provider." },
    createdAt: nullable(dateTime),
    updatedAt: nullable(dateTime),
  }),
  AuthProviderChange: obj(
    {
      preset: { type: "string", description: "Only when adding. Its name, scopes and groups claim are the defaults." },
      id: { type: "string", pattern: "^[a-z0-9-]{1,32}$", description: "Only when adding; part of the redirect URI. Default: the preset's id." },
      name: str,
      issuer: str,
      clientId: str,
      clientSecret: nullable(str),
      scopes: { type: "array", items: str },
      groupsClaim: nullable({ type: "string", description: "A claim name, or a dotted path such as realm_access.roles." }),
      roleMapping: { type: "object", additionalProperties: role },
      defaultRole: nullable(role),
      allowedDomains: { type: "array", items: str },
      enabled: { type: "boolean" },
      autoRedirect: { type: "boolean", description: "The sign-in screen goes straight to this provider. Refused while another has it." },
    },
    [],
  ),
  AuthDiscovery: obj({
    issuer: str,
    authorizationEndpoint: nullable(str),
    userinfoEndpoint: nullable(str),
    scopes: nullable({ type: "array", items: str }),
    pkce: { type: "boolean", description: "Whether the provider supports PKCE with S256, which sign-in uses." },
  }),
  AuthWebAuthnOptions: {
    type: "object",
    required: ["challenge"],
    description: "WebAuthn options as JSON, for navigator.credentials (or @simplewebauthn/browser).",
  },
};

const json = (schema: Schema, description = "OK") => ({ description, content: { "application/json": { schema } } });
const empty = (description: string) => ({ description });
const problems = (...codes: number[]) => Object.fromEntries(codes.map((c) => [String(c), { $ref: "#/components/responses/AuthProblem" }]));
const body = (schema: Schema) => ({ required: true, content: { "application/json": { schema } } });
const pathParam = (name: string) => ({ name, in: "path", required: true, schema: str });

const anyone: unknown[] = [];
const signedIn = [{ session: [] }];
const admin = [{ session: [] }, { apiToken: [] }];

interface Op {
  operationId: string;
  summary: string;
  description?: string;
  security: unknown[];
  role?: string;
  body?: Schema;
  params?: string[];
  responses: Record<string, unknown>;
}

const op = (o: Op) => ({
  operationId: o.operationId,
  tags: ["Sign-in"],
  summary: o.summary,
  ...(o.description && { description: o.description }),
  security: o.security,
  ...(o.params && { parameters: o.params.map(pathParam) }),
  ...(o.body && { requestBody: body(o.body) }),
  responses: o.responses,
  ...(o.role && { "x-openasy-role": o.role }),
});

const unsafe = [400, 403, 422];
const password = { type: "string", minLength: 12, maxLength: 256 };

const paths = {
  "/api/v1/auth/methods": {
    get: op({ operationId: "authMethods", summary: "How people can sign in", security: anyone, responses: { "200": json(ref("AuthMethods")) } }),
  },
  "/api/v1/auth/setup": {
    post: op({
      operationId: "authSetup",
      summary: "Create the owner",
      description:
        "Only once, with the token from the setup link printed in the log on first start (ADR 0013). With password sign-in off and a provider set up, the owner signs in through the provider instead: see /oidc/{id}/start.",
      security: anyone,
      body: obj({ token: str, name: str, email: str, password }),
      responses: { "200": json(ref("AuthSignedIn")), ...problems(...unsafe, 409) },
    }),
  },
  "/api/v1/auth/login": {
    post: op({
      operationId: "authLogin",
      summary: "Sign in with email and password",
      description: "Signs in, or asks for the second step: then send the code to /login/mfa or use /login/passkey.",
      security: anyone,
      body: obj({ email: str, password: str }),
      responses: { "200": json({ oneOf: [ref("AuthSignedIn"), ref("AuthMfaRequired")] }), ...problems(...unsafe, 401, 404, 429) },
    }),
  },
  "/api/v1/auth/login/mfa": {
    post: op({
      operationId: "authLoginMfa",
      summary: "Second step: authenticator code or recovery code",
      security: anyone,
      body: obj({ code: str, recoveryCode: str }, []),
      responses: { "200": json(ref("AuthSignedIn")), ...problems(...unsafe, 401, 429) },
    }),
  },
  "/api/v1/auth/login/passkey/options": {
    post: op({
      operationId: "authPasskeyOptions",
      summary: "Start signing in with a passkey",
      description: "Alone, or as the second step after a password.",
      security: anyone,
      responses: { "200": json(ref("AuthWebAuthnOptions")), ...problems(403) },
    }),
  },
  "/api/v1/auth/login/passkey": {
    post: op({
      operationId: "authPasskeyLogin",
      summary: "Finish signing in with a passkey",
      security: anyone,
      body: obj({ response: { type: "object" } }),
      responses: { "200": json(ref("AuthSignedIn")), ...problems(...unsafe, 401) },
    }),
  },
  "/api/v1/auth/brand/logo": {
    get: op({
      operationId: "authBrandLogo",
      summary: "The brand's logo",
      description: "The picture OPENASY_LOGO names (ADR 0053), kept for a year: its address changes with it. An SVG is sandboxed.",
      security: anyone,
      responses: {
        "200": {
          description: "The logo",
          content: Object.fromEntries(["image/svg+xml", "image/png", "image/webp"].map((t) => [t, { schema: { type: "string", format: "binary" } }])),
        },
        ...problems(404),
      },
    }),
  },
  "/api/v1/auth/brand/favicon": {
    get: op({
      operationId: "authBrandFavicon",
      summary: "The brand's tab icon",
      description: "The icon OPENASY_FAVICON names (ADR 0053), kept for a year: its address changes with it. An SVG is sandboxed.",
      security: anyone,
      responses: {
        "200": {
          description: "The icon",
          content: Object.fromEntries(["image/svg+xml", "image/png", "image/x-icon"].map((t) => [t, { schema: { type: "string", format: "binary" } }])),
        },
        ...problems(404),
      },
    }),
  },
  "/api/v1/auth/oidc/{id}/start": {
    get: op({
      operationId: "authOidcStart",
      summary: "Sign in through an identity provider",
      description:
        "Redirects the browser to the provider. `return` is a path on this product to come back to. `setup` is the token of the one-time setup link: the first person becomes the owner through the provider.",
      security: anyone,
      params: ["id"],
      responses: { "302": empty("To the identity provider"), ...problems(403, 404, 503) },
    }),
  },
  "/api/v1/auth/oidc/{id}/callback": {
    get: op({
      operationId: "authOidcCallback",
      summary: "Where the identity provider sends the browser back",
      description: "Register `<public URL>/api/v1/auth/oidc/<id>/callback` as the redirect URI. Errors redirect to the sign-in page with `?auth_error=`.",
      security: anyone,
      params: ["id"],
      responses: { "302": empty("To the product, signed in, or to the sign-in page with an error") },
    }),
  },
  "/api/v1/auth/logout": {
    post: op({ operationId: "authLogout", summary: "Sign out", security: anyone, responses: { "204": empty("Signed out"), ...problems(403) } }),
  },
  "/api/v1/auth/links/{token}": {
    get: op({
      operationId: "authLink",
      summary: "What an invitation or password link is for",
      security: anyone,
      params: ["token"],
      responses: { "200": json(obj({ kind: { type: "string", enum: ["invite", "reset"] }, email: str, name: str, productName: str })), ...problems(404) },
    }),
    post: op({
      operationId: "authAcceptLink",
      summary: "Choose a password with an invitation or password link",
      security: anyone,
      params: ["token"],
      body: obj({ password, name: str }, ["password"]),
      responses: { "200": json(ref("AuthSignedIn")), ...problems(...unsafe, 404) },
    }),
  },
  "/api/v1/auth/me": {
    get: op({ operationId: "authMe", summary: "The signed-in person", security: signedIn, responses: { "200": json(ref("AuthMe")), ...problems(401, 403) } }),
    patch: op({
      operationId: "authRename",
      summary: "Change your name",
      security: signedIn,
      body: obj({ name: str }),
      responses: { "200": json(ref("AuthMember")), ...problems(...unsafe, 401) },
    }),
  },
  "/api/v1/auth/me/password": {
    post: op({
      operationId: "authChangePassword",
      summary: "Change your password",
      description: "Signs out every other session.",
      security: signedIn,
      body: obj({ currentPassword: str, newPassword: password }, ["newPassword"]),
      responses: { "204": empty("Changed"), ...problems(...unsafe, 401) },
    }),
  },
  "/api/v1/auth/me/sessions": {
    get: op({
      operationId: "authSessions",
      summary: "Where you are signed in",
      security: signedIn,
      responses: { "200": json(obj({ sessions: { type: "array", items: ref("AuthSession") } })), ...problems(401, 403) },
    }),
  },
  "/api/v1/auth/me/sessions/{id}": {
    delete: op({
      operationId: "authRevokeSession",
      summary: "Sign out a session",
      security: signedIn,
      params: ["id"],
      responses: { "204": empty("Signed out"), ...problems(401, 403, 404) },
    }),
  },
  "/api/v1/auth/me/totp": {
    post: op({
      operationId: "authStartTotp",
      summary: "Start adding an authenticator app",
      description: "Returns the secret and an otpauth:// URI for a QR code; confirm with one code.",
      security: signedIn,
      responses: { "200": json(obj({ secret: str, uri: str })), ...problems(401, 403, 409) },
    }),
    delete: op({
      operationId: "authRemoveTotp",
      summary: "Remove the authenticator app",
      description: "Needs a session opened with a second factor.",
      security: signedIn,
      responses: { "204": empty("Removed"), ...problems(401, 403, 404) },
    }),
  },
  "/api/v1/auth/me/totp/confirm": {
    post: op({
      operationId: "authConfirmTotp",
      summary: "Turn on the authenticator app",
      description: "With the first second factor, the answer holds ten recovery codes, shown once.",
      security: signedIn,
      body: obj({ code: str }),
      responses: { "200": json(obj({ recoveryCodes: { type: "array", items: str } }, [])), ...problems(...unsafe, 401, 404) },
    }),
  },
  "/api/v1/auth/me/recovery-codes": {
    post: op({
      operationId: "authNewRecoveryCodes",
      summary: "Replace your recovery codes",
      security: signedIn,
      responses: { "200": json(ref("AuthRecoveryCodes")), ...problems(401, 403, 409) },
    }),
  },
  "/api/v1/auth/me/passkeys/options": {
    post: op({
      operationId: "authPasskeyRegisterOptions",
      summary: "Start adding a passkey",
      security: signedIn,
      responses: { "200": json(ref("AuthWebAuthnOptions")), ...problems(401, 403) },
    }),
  },
  "/api/v1/auth/me/passkeys": {
    post: op({
      operationId: "authAddPasskey",
      summary: "Add a passkey",
      security: signedIn,
      body: obj({ response: { type: "object" }, name: str }, ["response"]),
      responses: {
        "201": json(obj({ passkey: obj({ id: str, name: str, createdAt: dateTime }), recoveryCodes: { type: "array", items: str } }, ["passkey"]), "Added"),
        ...problems(...unsafe, 401),
      },
    }),
  },
  "/api/v1/auth/me/passkeys/{id}": {
    delete: op({
      operationId: "authRemovePasskey",
      summary: "Remove a passkey",
      security: signedIn,
      params: ["id"],
      responses: { "204": empty("Removed"), ...problems(401, 403, 404) },
    }),
  },
  "/api/v1/auth/members": {
    get: op({
      operationId: "authMembers",
      summary: "List members",
      security: admin,
      role: "admin",
      responses: { "200": json(obj({ members: { type: "array", items: ref("AuthMember") } })), ...problems(401, 403) },
    }),
    post: op({
      operationId: "authInvite",
      summary: "Invite a member",
      description: "Returns a one-time link for them to choose a password, valid for 7 days. Only owners invite owners.",
      security: signedIn,
      role: "admin",
      body: obj({ email: str, name: str, role }, ["email", "role"]),
      responses: {
        "201": json(obj({ member: ref("AuthMember"), link: { type: "string", format: "uri" }, linkExpiresAt: dateTime }), "Invited"),
        ...problems(...unsafe, 401, 409),
      },
    }),
  },
  "/api/v1/auth/members/{id}": {
    patch: op({
      operationId: "authUpdateMember",
      summary: "Change a member's role or disable them",
      description: "Disabling signs them out. There is always at least one owner.",
      security: signedIn,
      role: "admin",
      params: ["id"],
      body: obj({ role, status: { type: "string", enum: ["active", "disabled"] } }, []),
      responses: { "200": json(ref("AuthMember")), ...problems(...unsafe, 401, 404, 409) },
    }),
    delete: op({
      operationId: "authRemoveMember",
      summary: "Remove a member",
      security: signedIn,
      role: "admin",
      params: ["id"],
      responses: { "204": empty("Removed"), ...problems(401, 403, 404, 409) },
    }),
  },
  "/api/v1/auth/members/{id}/reset": {
    post: op({
      operationId: "authResetMember",
      summary: "New password link for a member",
      description: "Signs them out. With `mfa: true` their second factors are removed too.",
      security: signedIn,
      role: "admin",
      params: ["id"],
      body: obj({ mfa: { type: "boolean" } }, []),
      responses: { "200": json(ref("AuthResetLink")), ...problems(...unsafe, 401, 404, 409) },
    }),
  },
  "/api/v1/auth/tokens": {
    get: op({
      operationId: "authTokens",
      summary: "List API tokens",
      security: admin,
      role: "admin",
      responses: { "200": json(obj({ tokens: { type: "array", items: ref("AuthToken") } })), ...problems(401, 403) },
    }),
    post: op({
      operationId: "authCreateToken",
      summary: "Create an API token",
      description: "The secret is in `token` and is never shown again. The role is at most your own.",
      security: signedIn,
      role: "admin",
      body: obj({ name: str, role: tokenRole, expiresInDays: { type: "integer", minimum: 1, maximum: 366, default: 90 } }, ["name", "role"]),
      responses: { "201": json(obj({ id: str, name: str, role: tokenRole, expiresAt: dateTime, token: str }), "Created"), ...problems(...unsafe, 401) },
    }),
  },
  "/api/v1/auth/providers": {
    get: op({
      operationId: "authProviders",
      summary: "List identity providers",
      description: "The providers from the environment, then the ones added here. `redirectUriTemplate` is the callback address with `{id}` to fill in.",
      security: admin,
      role: "admin",
      responses: { "200": json(obj({ providers: { type: "array", items: ref("AuthProvider") }, redirectUriTemplate: str })), ...problems(401, 403) },
    }),
    post: op({
      operationId: "authAddProvider",
      summary: "Add an identity provider",
      description: "Only owners, because a role mapping can make anyone in a group an owner. The client secret is sealed with the secrets key.",
      security: signedIn,
      role: "owner",
      body: ref("AuthProviderChange"),
      responses: { "201": json(ref("AuthProvider"), "Added"), ...problems(...unsafe, 401, 409) },
    }),
  },
  "/api/v1/auth/providers/{id}": {
    patch: op({
      operationId: "authUpdateProvider",
      summary: "Change an identity provider",
      description:
        "Fields left out keep their value; `clientSecret: null` removes the secret. A new issuer unlinks everyone who signed in through the old one.",
      security: signedIn,
      role: "owner",
      params: ["id"],
      body: ref("AuthProviderChange"),
      responses: { "200": json(ref("AuthProvider")), ...problems(...unsafe, 401, 404, 409) },
    }),
    delete: op({
      operationId: "authRemoveProvider",
      summary: "Remove an identity provider",
      description: "People who signed in through it stay members but are unlinked from it.",
      security: signedIn,
      role: "owner",
      params: ["id"],
      responses: { "204": empty("Removed"), ...problems(401, 403, 404, 409) },
    }),
  },
  "/api/v1/auth/providers/discover": {
    post: op({
      operationId: "authDiscoverProvider",
      summary: "Check an issuer",
      description: "Reads the provider's discovery document, so a wrong issuer shows before it is saved.",
      security: signedIn,
      role: "owner",
      body: obj({ issuer: str }),
      responses: { "200": json(ref("AuthDiscovery")), ...problems(...unsafe, 401) },
    }),
  },
  "/api/v1/auth/tokens/{id}": {
    delete: op({
      operationId: "authRevokeToken",
      summary: "Revoke an API token",
      security: signedIn,
      role: "admin",
      params: ["id"],
      responses: { "204": empty("Revoked"), ...problems(401, 403, 404) },
    }),
  },
};

/** The paths, schemas and security schemes of /api/v1/auth, as an OpenAPI 3.1 fragment. */
export function authOpenApi() {
  return {
    tags: [{ name: "Sign-in", description: "Accounts, second factors, sessions, members and API tokens (@openasy/auth)." }],
    paths,
    components: {
      schemas,
      responses: {
        AuthProblem: { description: "An error, as RFC 9457 Problem Details.", content: { "application/problem+json": { schema: ref("AuthProblem") } } },
      },
      securitySchemes: {
        session: {
          type: "apiKey",
          in: "cookie",
          name: "__Host-openasy-session",
          description: "The browser session after signing in (`openasy-session` on plain http://localhost).",
        },
        apiToken: { type: "http", scheme: "bearer", description: "An API token from Settings → API tokens: one role, always an expiry." },
      },
    },
  };
}

type Spec = Record<string, unknown> & { tags?: unknown[]; paths?: Record<string, unknown>; components?: Record<string, Record<string, unknown>> };

/** The product's description with /api/v1/auth added. The product's own components win on a name clash. */
export function mergeOpenApi<T extends Spec>(spec: T, fragment = authOpenApi()): T {
  const components = { ...spec.components } as Record<string, Record<string, unknown>>;
  for (const [kind, entries] of Object.entries(fragment.components)) components[kind] = { ...entries, ...components[kind] };
  return { ...spec, tags: [...(spec.tags ?? []), ...fragment.tags], paths: { ...spec.paths, ...fragment.paths }, components };
}
