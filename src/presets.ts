// Settings for the identity providers people use most (ADR 0033). Products use them in Settings → Sign-in and in
// OPENASY_OIDC_PROVIDER, and Identity for its upstream providers, so every place gives the same help. No Node imports:
// the React screens use this file too.

export interface ProviderPreset {
  id: string;
  /** On the sign-in button: "Continue with <name>". */
  name: string;
  /** What the issuer looks like, with the parts to replace in angle brackets. */
  issuerExample: string;
  scopes: string[];
  /**
   * Where group or role names are: a claim name, or a dotted path into nested claims such as realm_access.roles.
   * Undefined when the provider sends no groups, so access is by invitation, default role or email domain.
   */
  groupsClaim?: string;
  /** What to do at the provider, in order. `{redirectUri}` is replaced with this product's callback address. */
  steps: string[];
  /** What people get wrong most often. */
  notes?: string[];
  docs: string;
}

export const PRESETS: ProviderPreset[] = [
  {
    id: "keycloak",
    name: "Keycloak",
    issuerExample: "https://keycloak.example.com/realms/<realm>",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "groups",
    steps: [
      "In your realm, open Clients and create a client of type OpenID Connect, with Client authentication on and only the Standard flow.",
      "Set Valid redirect URIs to {redirectUri}.",
      "Under the client's Client scopes, open its dedicated scope and add a Group Membership mapper with the token claim name groups and Full group path off.",
      "Copy the client secret from the Credentials tab.",
    ],
    notes: [
      "To map realm roles instead of groups, set the groups claim to realm_access.roles; for client roles, resource_access.<client>.roles.",
      "Users need an email address marked as verified in Keycloak to be linked to someone who was invited.",
    ],
    docs: "https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients",
  },
  {
    id: "entra",
    name: "Microsoft",
    issuerExample: "https://login.microsoftonline.com/<tenant-id>/v2.0",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "groups",
    steps: [
      "In Microsoft Entra ID, open App registrations and create a registration for accounts in this organizational directory only.",
      "Add a Web redirect URI: {redirectUri}.",
      "Under Certificates & secrets, create a client secret and copy its value.",
      "Under Token configuration, add a groups claim. Choose Groups assigned to the application, so large organizations stay under the limit of groups a token can hold.",
    ],
    notes: [
      "Entra sends group object IDs, not names: use those IDs in the role mapping.",
      "Entra does not say an email address is verified, so invited people are not linked by email. Let people be created on their first sign-in, with the role mapping or a default role, instead of inviting them.",
    ],
    docs: "https://learn.microsoft.com/entra/identity-platform/quickstart-register-app",
  },
  {
    id: "okta",
    name: "Okta",
    issuerExample: "https://<your-org>.okta.com",
    scopes: ["openid", "email", "profile", "groups"],
    groupsClaim: "groups",
    steps: [
      "In the Okta admin console, open Applications and create an OIDC Web Application.",
      "Set the Sign-in redirect URI to {redirectUri} and assign the groups that may sign in.",
      "On the Sign On tab, edit the OpenID Connect ID Token and set the Groups claim filter to groups, matching the groups you map.",
      "Copy the client ID and the client secret.",
    ],
    docs: "https://developer.okta.com/docs/guides/customize-tokens-groups-claim/",
  },
  {
    id: "google",
    name: "Google",
    issuerExample: "https://accounts.google.com",
    scopes: ["openid", "email", "profile"],
    steps: [
      "In the Google Cloud console, open APIs & Services, Credentials, and create an OAuth client ID of type Web application.",
      "Add the authorized redirect URI {redirectUri}.",
      "Copy the client ID and the client secret.",
    ],
    notes: [
      "Google sends no groups. Limit sign-in to your Workspace domain with the allowed domains, and give people a role by inviting them or with a default role.",
    ],
    docs: "https://developers.google.com/identity/openid-connect/openid-connect",
  },
  {
    id: "authentik",
    name: "authentik",
    issuerExample: "https://authentik.example.com/application/o/<application-slug>/",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "groups",
    steps: [
      "In authentik, open Applications, Providers, and create an OAuth2/OpenID Provider with the client type Confidential.",
      "Set the redirect URI to {redirectUri}.",
      "Create an application that uses the provider; its slug is part of the issuer.",
      "Copy the client ID and the client secret from the provider.",
    ],
    docs: "https://docs.goauthentik.io/docs/add-secure-apps/providers/oauth2/",
  },
  {
    id: "zitadel",
    name: "ZITADEL",
    issuerExample: "https://<instance>.zitadel.cloud",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "urn:zitadel:iam:org:project:roles",
    steps: [
      "In your project, create a Web application with the authentication method Code (client secret).",
      "Add the redirect URI {redirectUri}.",
      "In the project's settings, turn on Assert Roles on Authentication, so the roles are in the ID token.",
      "Copy the client ID and the client secret.",
    ],
    notes: ["Map the project's role keys, not the names shown in the console."],
    docs: "https://zitadel.com/docs/guides/integrate/login/oidc",
  },
  {
    id: "openasy-identity",
    name: "OpenAsy Identity",
    issuerExample: "https://id.example.com",
    scopes: ["openid", "email", "profile", "groups"],
    groupsClaim: "groups",
    steps: [
      "In Identity, open Applications and add this product from its template; the redirect URI {redirectUri} is filled in.",
      "Choose the groups that may sign in, and copy the client ID and the client secret.",
    ],
    docs: "https://openasy.github.io/products/identity",
  },
  {
    id: "generic",
    name: "SSO",
    issuerExample: "https://idp.example.com",
    scopes: ["openid", "email", "profile"],
    groupsClaim: "groups",
    steps: [
      "Register a confidential client using the authorization code flow, with the redirect URI {redirectUri}.",
      "Copy the client ID and the client secret.",
    ],
    docs: "https://openid.net/specs/openid-connect-core-1_0.html",
  },
];

export const preset = (id: string) => PRESETS.find((p) => p.id === id);
