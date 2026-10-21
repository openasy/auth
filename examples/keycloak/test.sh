#!/bin/bash
# Starts Keycloak with the realm here and signs in through it (test/keycloak.test.ts). Needs Docker. Used by CI.
set -eu
cd "$(dirname "$0")/../.."
NAME=openasy-keycloak-test
export KEYCLOAK_URL=http://localhost:18080 KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 12) OPENASY_VPN_SECRET=$(openssl rand -hex 16)
docker rm -f "$NAME" >/dev/null 2>&1 || true
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$NAME" -p 18080:8080 \
  -v "$PWD/examples/keycloak/openasy-realm.json:/opt/keycloak/data/import/openasy-realm.json:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
  -e OPENASY_VPN_URL=http://localhost:4100 -e OPENASY_VPN_SECRET \
  -e OPENASY_INFRA_URL=https://infra.example.com -e OPENASY_INFRA_SECRET=unused \
  -e OPENASY_VULNS_URL=https://vulns.example.com -e OPENASY_VULNS_SECRET=unused \
  -e OPENASY_IDENTITY_URL=https://id.example.com -e OPENASY_IDENTITY_SECRET=unused \
  "$(grep -o 'quay.io/keycloak/keycloak:[0-9.]*' examples/keycloak/compose.yaml)" start-dev --import-realm >/dev/null
for _ in $(seq 1 120); do curl -sf "$KEYCLOAK_URL/realms/openasy/.well-known/openid-configuration" >/dev/null && break; sleep 2; done
npx vitest run test/keycloak.test.ts
