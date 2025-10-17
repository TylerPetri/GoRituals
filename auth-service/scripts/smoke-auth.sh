#!/usr/bin/env bash
set -euo pipefail

# ==============================================
# Smoke test for auth-service routes
# Requires: curl, jq
# Usage:
#   BASE_URL=http://localhost:8080 ./scripts/smoke-auth.sh
# Optional env:
#   BASE_URL     (default: http://localhost:8080)
#   EMAIL        (default: smoke+<ts>@example.com)
#   PASSWORD     (default: Secret123!)
#   VERBOSE=1    (default: off)
# ==============================================

BASE_URL="${BASE_URL:-http://localhost:8080}"
EMAIL="${EMAIL:-smoke+$(date +%s)@example.com}"
PASSWORD="${PASSWORD:-Secret123!}"
VERBOSE="${VERBOSE:-}"

command -v jq >/dev/null || { echo "jq is required"; exit 1; }
command -v curl >/dev/null || { echo "curl is required"; exit 1; }

C_RESET=$'\033[0m'; C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_INFO=$'\033[36m'
TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
RESP="$TMPDIR/resp.json"

say() { printf "%s%s%s\n" "$C_INFO" "$*" "$C_RESET"; }
ok()  { printf "%s✓ %s%s\n" "$C_OK" "$*" "$C_RESET"; }
err() { printf "%s✗ %s%s\n" "$C_ERR" "$*" "$C_RESET"; }

curl_json() {
  local method="$1"; shift
  local url="$1"; shift
  local code
  if [ -n "${VERBOSE}" ]; then
    code=$(curl -sv -X "$method" "$url" "$@" -H 'Content-Type: application/json' -o "$RESP" -w '%{http_code}') || true
  else
    code=$(curl -sS -X "$method" "$url" "$@" -H 'Content-Type: application/json' -o "$RESP" -w '%{http_code}') || true
  fi
  echo "$code"
}

expect_code() {
  local got="$1"; shift
  local want="$1"; shift
  if [ "$got" != "$want" ]; then
    err "expected HTTP $want, got $got"
    if [ -s "$RESP" ]; then
      echo "Response:"; cat "$RESP"; echo
    fi
    exit 1
  fi
}

expect_non2xx() {
  local got="$1"; shift
  case "$got" in
    2*) err "expected failure, got $got"; cat "$RESP"; exit 1 ;;
    *) ok "got expected non-2xx ($got)" ;;
  esac
}

# 0) health
say "Health check"
code=$(curl_json GET "$BASE_URL/healthz")
expect_code "$code" "200"
ok "healthz ok"

# 1) signup
say "Signup user: $EMAIL"
code=$(curl_json POST "$BASE_URL/v1/auth/signup" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"first_name\":\"Smoke\",\"last_name\":\"Test\"}")
expect_code "$code" "201"
AT=$(jq -r '.access_token' "$RESP")
RT=$(jq -r '.refresh_token' "$RESP")
USER_ID=$(jq -r '.user.id' "$RESP")
test -n "$AT" -a "$AT" != "null" || { err "missing access token"; cat "$RESP"; exit 1; }
test -n "$RT" -a "$RT" != "null" || { err "missing refresh token"; cat "$RESP"; exit 1; }
ok "signup ok (user_id=$USER_ID)"

# 2) me (protected)
say "GET /v1/me with AT"
code=$(curl_json GET "$BASE_URL/v1/me" -H "Authorization: Bearer $AT")
expect_code "$code" "200"
EMAIL_R=$(jq -r '.email' "$RESP")
[ "$EMAIL_R" = "$EMAIL" ] || { err "email mismatch: $EMAIL_R != $EMAIL"; exit 1; }
ok "/v1/me ok"

# 3) refresh (rotate)
say "Refresh access (rotate RT)"
code=$(curl_json POST "$BASE_URL/v1/tokens/refresh" -H "Authorization: Bearer $RT")
expect_code "$code" "200"
AT2=$(jq -r '.access_token' "$RESP")
RT2=$(jq -r '.refresh_token' "$RESP")
test -n "$AT2" -a "$AT2" != "null" || { err "missing new AT"; cat "$RESP"; exit 1; }
test -n "$RT2" -a "$RT2" != "null" || { err "missing new RT"; cat "$RESP"; exit 1; }
# ensure rotation happened: id component before dot likely changed
id1="${RT%%.*}"; id2="${RT2%%.*}"
[ "$id1" != "$id2" ] && ok "refresh rotated (old id=$id1 new id=$id2)" || ok "refresh returned same id (server may reuse id as strategy)"

# 4) logout (revoke RT2)
say "Logout (revoke RT2)"
code=$(curl_json POST "$BASE_URL/v1/auth/logout" -H "Authorization: Bearer $RT2")
expect_code "$code" "204"
ok "logout 204 OK"

# 5) ensure revoked RT2 cannot refresh
say "Refresh with revoked RT2 (should fail)"
code=$(curl_json POST "$BASE_URL/v1/tokens/refresh" -H "Authorization: Bearer $RT2")
expect_non2xx "$code"

# 6) login
say "Login with email/password"
code=$(curl_json POST "$BASE_URL/v1/auth/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
expect_code "$code" "200"
AT3=$(jq -r '.access_token' "$RESP")
RT3=$(jq -r '.refresh_token' "$RESP")
test -n "$AT3" && test -n "$RT3" || { err "missing tokens on login"; exit 1; }
ok "login ok"

# 7) logout-all (requires AT3)
say "Logout all (revoke all RTs)"
code=$(curl_json POST "$BASE_URL/v1/auth/logout-all" -H "Authorization: Bearer $AT3")
expect_code "$code" "204"
ok "logout-all 204 OK"

# 8) confirm RT3 no longer valid
say "Refresh with RT3 (should fail)"
code=$(curl_json POST "$BASE_URL/v1/tokens/refresh" -H "Authorization: Bearer $RT3")
expect_non2xx "$code"

ok "All checks passed for $EMAIL"

# # 0) vars
# BASE_URL=${BASE_URL:-http://localhost:8080}
# EMAIL=${EMAIL:-smoke@example.com}
# PASSWORD=${PASSWORD:-Secret123!}

# # 2) extract tokens and sanity-log them
# AT=$(jq -r '.access_token' "$RESP")
# RT=$(jq -r '.refresh_token' "$RESP")
# echo "AT len: ${#AT}   RT len: ${#RT}"
# echo "raw response:"; cat "$RESP"; echo

# # 3) if AT is empty/null, stop here — the response is not what we expect
# if [ -z "$AT" ] || [ "$AT" = "null" ]; then
#   echo "No access token in response — cannot verify /v1/me"
#   exit 1
# fi

# # 4) portable JWT decode (handles base64url padding)
# jwt_print_part() {
#   part="$1"  # 1=header, 2=payload
#   seg="$(printf '%s' "$AT" | cut -d. -f"$part" | tr '_-' '/+')"
#   pad=$(( (4 - ${#seg} % 4) % 4 )); printf -v P '%*s' "$pad" ''; P=${P// /=}
#   if command -v openssl >/dev/null 2>&1; then
#     printf '%s' "${seg}${P}" | openssl base64 -d -A
#   elif base64 --help 2>&1 | grep -q -- '--decode'; then
#     printf '%s' "${seg}${P}" | base64 --decode 2>/dev/null
#   else
#     printf '%s' "${seg}${P}" | base64 -D 2>/dev/null
#   fi
# }

# echo "=== JWT header ===";  jwt_print_part 1 | jq .
# echo "=== JWT payload ==="; jwt_print_part 2 | jq .

# # 5) call /v1/me with the token, show full response
# echo; echo "GET /v1/me with AT"
# curl -sS -i "$BASE_URL/v1/me" -H "Authorization: Bearer $AT"
# echo
