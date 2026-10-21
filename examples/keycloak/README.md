# Keycloak for OpenAsy

A Keycloak that is ready for every OpenAsy product: the realm `openasy` has a client for VPN, Infrastructure,
Vulnerabilities and Identity, the groups `openasy-admins`, `openasy-editors` and `openasy-viewers`, and a `groups`
claim each product reads. Use it if you want Keycloak and do not run one yet; if you do, add the clients to yours
the same way.

```bash
cp .env.example .env    # the addresses people open Keycloak and each product at, and a secret per client
docker compose up -d
```

Keycloak listens on 127.0.0.1:8180; put it behind your TLS proxy at `KEYCLOAK_URL`. Then:

1. Sign in to Keycloak's console at `KEYCLOAK_URL/admin` as `admin` and change the password.
2. In the realm `openasy`, add people and put them in a group.
3. In each product, open Settings, Sign-in, add a provider and choose Keycloak:
   - Issuer: `KEYCLOAK_URL/realms/openasy`
   - Client ID: `openasy-vpn`, `openasy-infrastructure`, `openasy-vulnerabilities` or `openasy-identity`
   - Client secret: that client's secret from `.env`
   - Roles from groups: `openasy-admins = admin`, `openasy-editors = editor`, `openasy-viewers = viewer`

Each client accepts the product's callback both as a provider added under Settings (`/api/v1/auth/oidc/keycloak/callback`)
and from the environment (`/api/v1/auth/oidc/sso/callback`), and asks for PKCE.

The realm is imported on the first start only. Change it afterwards in Keycloak's console; `--import-realm` never
overwrites a realm that exists.

`test.sh` starts this realm in Keycloak's development mode and signs in through it, as CI does on every change.
