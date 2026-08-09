#!/bin/sh
# Is the pair actually usable — not merely "containers exist"? Probes what a
# client would hit: entra's discovery document and apim's health endpoint.
set -u

ENTRA_PORT="${ENTRA_PORT:-8443}"
APIM_PORT="${APIM_PORT:-8446}"
TENANT="6f89cf12-978b-4d23-ac18-9ef0c127cf87"
fail=0
ok()   { printf '  ok    %-18s %s\n' "$1" "$2"; }
FAIL() { printf '  FAIL  %-18s %s\n' "$1" "$2"; fail=1; }

echo "containers"
docker compose -f compose.yaml ps --format '  {{.Service}}  {{.Status}}' 2>/dev/null || true

echo "endpoints"
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${ENTRA_PORT}/${TENANT}/v2.0/.well-known/openid-configuration" 2>/dev/null)
[ "$code" = "200" ] && ok "entra discovery" "HTTP 200" || FAIL "entra discovery" "HTTP ${code:-none} (want 200)"

code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${APIM_PORT}/health" 2>/dev/null)
[ "$code" = "200" ] && ok "apim /health" "HTTP 200" || FAIL "apim /health" "HTTP ${code:-none} (want 200)"

# The seam: an unauthenticated management call must be REFUSED, or the pair is
# up but the gate is not real.
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${APIM_PORT}/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.ApiManagement/service?api-version=2024-05-01" 2>/dev/null)
[ "$code" = "401" ] && ok "management gate" "401 without a token" || FAIL "management gate" "HTTP ${code:-none} (want 401)"

[ $fail = 0 ] && echo "pair is usable" || echo "pair has problems (see FAIL above)"
exit $fail
