#!/usr/bin/env bash
# scan_auth_security.sh - static grep scan for auth/Postgres/Supabase security
# red flags. Read-only: no network calls, no edits, no execution of repo code.
# Heuristic only - confirm every hit by hand.
#
# Usage:  scan_auth_security.sh [path]      (defaults to current directory)
# Exit:   0 = no matches; 1 = one or more pattern groups matched

set -uo pipefail
ROOT="${1:-.}"

EXCLUDES=(
  --exclude-dir=node_modules --exclude-dir=.git
  --exclude-dir=dist --exclude-dir=build --exclude-dir=.next
  --exclude-dir=.turbo --exclude-dir=.vercel --exclude-dir=.wrangler
  --exclude-dir=vendor --exclude-dir=.venv --exclude-dir=venv
  --exclude-dir=__pycache__ --exclude-dir=coverage
)

HITS=0

# ── helper ────────────────────────────────────────────────────────────────────
check() {
  local label="$1" pattern="$2"
  shift 2
  local results
  results=$(grep -rnEi "${EXCLUDES[@]}" "$@" -- "$pattern" "$ROOT" 2>/dev/null || true)
  if [[ -n "$results" ]]; then
    printf '\n### %s\n%s\n' "$label" "$results"
    HITS=$(( HITS + 1 ))
  fi
}

echo "=== postgres-auth-security-review scanner v1.2.0 ==="
echo "Scanning: $ROOT"
echo "(Heuristic - every hit needs human review. Not a guarantee of a bug.)"

# ── A. PostgreSQL version ─────────────────────────────────────────────────────
check \
  "A. Outdated Postgres image (pre-patch for CVE-2025-1094/CVE-2026-2004/5)" \
  'postgres:(14\.(0|[1-9]|1[0-9]|2[0-2])|15\.(0|[0-9]|1[0-7])|16\.(0|[0-9]|1[0-3])|17\.(0|[0-9])|18\.[0-3])[^0-9]' \
  --include="*.yml" --include="*.yaml" --include="*.env" \
  --include="Dockerfile" --include="*.toml" --include="*.tf"

# ── B. RLS ────────────────────────────────────────────────────────────────────
check \
  "B1. USING (true) - permissive RLS policy (no restriction)" \
  'USING[[:space:]]*\([[:space:]]*(true|TRUE)[[:space:]]*\)' \
  --include="*.sql"

check \
  "B2. WITH CHECK (true) - permissive RLS write policy" \
  'WITH[[:space:]]+CHECK[[:space:]]*\([[:space:]]*(true|TRUE)[[:space:]]*\)' \
  --include="*.sql"

# Files with CREATE TABLE but no ENABLE ROW LEVEL SECURITY
while IFS= read -r f; do
  if ! grep -qE 'ENABLE[[:space:]]+ROW[[:space:]]+LEVEL[[:space:]]+SECURITY' "$f" 2>/dev/null; then
    printf '\n### B3. CREATE TABLE without ENABLE ROW LEVEL SECURITY in same file\n%s\n' "$f"
    HITS=$(( HITS + 1 ))
  fi
done < <(grep -rlE "${EXCLUDES[@]}" 'CREATE[[:space:]]+TABLE' --include="*.sql" "$ROOT" 2>/dev/null || true)

check \
  "B4. MATERIALIZED VIEW - confirm it does not expose user-specific rows (RLS does not apply at query time)" \
  'CREATE[[:space:]]+(OR[[:space:]]+REPLACE[[:space:]]+)?MATERIALIZED[[:space:]]+VIEW' \
  --include="*.sql"

# ── C. Service-role / secret key exposure ─────────────────────────────────────
check \
  "C1. Supabase service_role key in NEXT_PUBLIC env var (RLS bypass in browser)" \
  'NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SECRET)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.env" --include="*.env.*" --include="*.mjs"

check \
  "C2. service_role JWT eyJ prefix in source file (potential key leak)" \
  '(service_role|SERVICE_ROLE)[^=\n]{0,30}eyJ[A-Za-z0-9_-]{10}' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.env" --include="*.env.*" --include="*.json"

check \
  "C3. Hardcoded Postgres connection string with embedded password" \
  'postgres(ql)?://[^:/[:space:]"'"'"']{1,64}:[^@/[:space:]"'"'"']{1,64}@' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.py" --include="*.go" --include="*.rs" --include="*.java" \
  --include="*.env" --include="*.env.*"

# ── D. SSL / TLS ──────────────────────────────────────────────────────────────
check \
  "D. sslmode=disable on a Postgres connection (plaintext on the wire)" \
  'sslmode[[:space:]]*=[[:space:]]*disable'

# ── E. Password hashing ───────────────────────────────────────────────────────
check \
  "E1. md5() or crypt() near password handling in SQL" \
  '\b(md5|crypt)\s*\(' \
  --include="*.sql"

check \
  "E2. MD5 password hashing in application code" \
  '(md5|MD5)\s*\(.*(password|passwd|pwd|secret)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.py" --include="*.rb" --include="*.php" --include="*.java" \
  --include="*.go"

check \
  "E3. bcrypt cost factor below 12 (insufficient in 2026)" \
  'genSalt\s*\(\s*([0-9]|1[01])\s*\)|bcrypt\.hash\(.*,\s*([0-9]|1[01])\s*\)|rounds\s*[:=]\s*([0-9]|1[01])\b'

# ── F. Custom JWT (crypto.subtle / HMAC) ──────────────────────────────────────
# F1: crypto.subtle used without alg:none rejection nearby
check \
  "F1. crypto.subtle JWT usage - confirm alg:none is explicitly rejected before verify()" \
  'crypto\.subtle\.(sign|verify|importKey)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs"

# F2: token claims read before verify() call (authentication bypass pattern)
check \
  "F2. JWT payload parsed/destructured before crypto.subtle.verify() - claims must not be trusted before signature check" \
  'JSON\.parse\(atob|JSON\.parse\(Buffer\.from.*base64' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs"

# F3: === used to compare tokens or HMAC results (timing attack)
check \
  "F3. Token compared with === or == (use crypto.timingSafeEqual or crypto.subtle.verify instead)" \
  '(token|hash|hmac|signature|digest)\s*(===|==)\s*(token|hash|hmac|signature|digest|[a-zA-Z_][a-zA-Z0-9_]*)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs"

# F4: Long JWT expiry (> 24h) - risky for stolen-token scenarios
check \
  "F4. JWT expiry > 24h - stolen tokens cannot be invalidated without rotating the signing secret" \
  'expiresIn\s*[:=]\s*['"'"'"]?(([2-9]|[1-9][0-9]+)d|[7-9]h|[1-9][0-9]+h|168h|604800|[1-9][0-9]{5,})' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs" --include="*.json"

# ── G. Standard JWT library ───────────────────────────────────────────────────
_g1=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.mjs" -- '\bjwt\.verify\s*\(' "$ROOT" 2>/dev/null | grep -v 'algorithms' || true)
if [[ -n "$_g1" ]]; then
  printf '\n### G1. jwt.verify without explicit algorithms option (algorithm-confusion attack)\n%s\n' "$_g1"
  HITS=$(( HITS + 1 ))
fi

check \
  "G2. alg:none accepted - JWT signature requirement disabled" \
  '"alg"\s*:\s*"[Nn][Oo][Nn][Ee]"' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.json" --include="*.py"

check \
  "G3. JWT stored in localStorage or sessionStorage (XSS-readable)" \
  'localStorage\.(set|get)Item.*[Tt]oken|sessionStorage\.(set|get)Item.*[Tt]oken' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx"

# ── H. Serverless / edge routing ─────────────────────────────────────────────
# H1: catch-all route file without an obvious auth guard at the top
check \
  "H1. Catch-all edge/serverless route - confirm top-level auth guard wraps all handlers (not per-handler)" \
  '\[\[path\]\]|\[\.\.\.slug\]|catchall|catch_all' \
  --include="*.js" --include="*.ts" --include="*.mjs"

# H2: module-scope mutable variable (can leak between warm requests)
check \
  "H2. Module-scope mutable variable in edge function - may leak between concurrent requests" \
  '^(let|var)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*[=;]' \
  --include="*.js" --include="*.ts" --include="*.mjs"

# H3: Next.js middleware bypass
check \
  "H3. CVE-2025-29927: x-middleware-subrequest not stripped at proxy level" \
  'x-middleware-subrequest' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.yml" --include="*.yaml" --include="*.json" --include="*.conf"

check \
  "H4. Next.js middleware.ts exists - verify auth also enforced in API routes" \
  '(export function middleware|export default.*middleware)' \
  --include="*.ts" --include="*.js"

# ── I. Object storage (R2 / S3 / GCS) ───────────────────────────────────────
# I1: pre-signed URL without expiry parameter
check \
  "I1. Pre-signed URL generated without expiry - add expiresIn / Expires parameter" \
  '(getSignedUrl|createPresignedUrl|generatePresignedUrl|presign)\s*\([^)]{0,300}\)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.py" --include="*.go" \
  | grep -v 'expires\|Expires\|expiry\|ExpiresIn\|expiresIn' || true

_i1=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" --include="*.go" -- '(getSignedUrl|createPresignedUrl|generatePresignedUrl|presign)\s*\(' "$ROOT" 2>/dev/null | grep -vi 'expires\|expiry\|expiresIn' || true)
if [[ -n "$_i1" ]]; then
  printf '\n### I1. Pre-signed URL without expiry parameter\n%s\n' "$_i1"
  HITS=$(( HITS + 1 ))
fi

# I2: object key constructed from user ID (IDOR at storage layer)
check \
  "I2. Object key/path built from user_id or numeric ID - use random UUIDs instead to prevent IDOR" \
  '(key|path|object_key|objectKey)\s*[=:]\s*[`'"'"'"][^`'"'"'"]*\$\{.*(user_id|userId|uid|id)[^}]*\}' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs"

# I3: public bucket config
check \
  "I3. Public bucket access policy - documents bucket must be private" \
  '(public[_-]?read|PublicRead|public-read|AllPublicAccess|\"public\")' \
  --include="*.json" --include="*.tf" --include="*.yml" --include="*.yaml" \
  --include="*.ts" --include="*.js"

# ── J. SQL injection ──────────────────────────────────────────────────────────
check \
  "J1. SQL built with string concatenation in application code" \
  '(SELECT|INSERT|UPDATE|DELETE)\b.{0,300}[+]\s*\w' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.py" --include="*.rb" --include="*.php" --include="*.java" \
  --include="*.go"

check \
  "J2. EXECUTE inside PL/pgSQL with string concatenation (DB-layer injection)" \
  'EXECUTE\s+['"'"'"][^'"'"'"]*\|\|' \
  --include="*.sql"

check \
  "J3. PQescapeLiteral / PQescapeIdentifier on untrusted input (CVE-2025-1094 class)" \
  'PQescapeLiteral|PQescapeIdentifier|PQescapeString' \
  --include="*.c" --include="*.cpp" --include="*.h"

# ── K. SECURITY DEFINER ───────────────────────────────────────────────────────
_k=$(grep -rnEi "${EXCLUDES[@]}" --include="*.sql" -- 'SECURITY[[:space:]]+DEFINER' "$ROOT" 2>/dev/null | grep -v 'search_path' || true)
if [[ -n "$_k" ]]; then
  printf '\n### K. SECURITY DEFINER without SET search_path (privilege escalation)\n%s\n' "$_k"
  HITS=$(( HITS + 1 ))
fi

# ── L. Custom RLS session binding ────────────────────────────────────────────
# L1: set_config without is_local=true (session-scoped - leaks between pooled requests)
check \
  "L1. set_config without is_local=true - session-scoped variable leaks across pooled connections" \
  "set_config\s*\([^)]*,\s*(false|0)\s*\)" \
  --include="*.sql"

# L2: is_admin / similar check that might fail-open (EXCEPTION WHEN OTHERS THEN RETURN true)
check \
  "L2. Exception handler returning true/admin in auth function - fails open if error occurs" \
  'EXCEPTION\s+WHEN\s+OTHERS\s+THEN\s+(RETURN\s+true|RETURN\s+1)' \
  --include="*.sql"

# L3: session-binding RPC called without error handling in app code
check \
  "L3. RLS session-binding RPC (set_current_user/set_config) called without await error handling" \
  '\.(rpc|from)\s*\(\s*['"'"'"](set_current_user|set_config)['"'"'"]' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs" \
  | grep -v 'try\|catch\|\.error\|throw\|await.*catch' || true

_l3=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.mjs" -- '\.(rpc|from)\s*\(\s*['"'"'"](set_current_user|set_config)['"'"'"]' "$ROOT" 2>/dev/null | grep -v 'catch\|\.error\|throw' || true)
if [[ -n "$_l3" ]]; then
  printf '\n### L3. RLS session-binding RPC without visible error handling\n%s\n' "$_l3"
  HITS=$(( HITS + 1 ))
fi

# ── M. Rate limiting ──────────────────────────────────────────────────────────
check \
  "M1. Rate-limit IP from X-Forwarded-For - use CF-Connecting-IP or X-Real-IP (platform-verified)" \
  'X-Forwarded-For.*(rate.limit|rate_limit|ip.address|ip_address)|(rate.limit|rate_limit).*X-Forwarded-For' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs" --include="*.py"

check \
  "M2. X-Forwarded-For used as IP source without validation" \
  "get\s*\(\s*['\"]X-Forwarded-For['\"]|headers\[.X-Forwarded-For.\]" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs" --include="*.py" --include="*.go"

# ── N. Session and cookie security ───────────────────────────────────────────
_n1=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" -- 'cookie\s*\([^)]*\)' "$ROOT" 2>/dev/null | grep -vi 'httponly\|http_only' || true)
if [[ -n "$_n1" ]]; then
  printf '\n### N1. Cookie set without httpOnly flag\n%s\n' "$_n1"
  HITS=$(( HITS + 1 ))
fi

_n2=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" -- 'SameSite\s*=\s*None' "$ROOT" 2>/dev/null | grep -vi 'secure' || true)
if [[ -n "$_n2" ]]; then
  printf '\n### N2. SameSite=None without Secure flag (CSRF risk)\n%s\n' "$_n2"
  HITS=$(( HITS + 1 ))
fi

# ── O. Minor / guardian consent ───────────────────────────────────────────────
# O1: age check only in client-side component files
check \
  "O1. Age/minor check in client component - must also exist server-side (easy to bypass on client)" \
  '(getAgeYears|calculateAge|isMinor|age\s*<\s*18|dob|date_of_birth)' \
  --include="*.tsx" --include="*.jsx"

# O2: consent table without immutability policy
check \
  "O2. legal_consents / consent table - confirm UPDATE is blocked via RLS WITH CHECK (false)" \
  'CREATE[[:space:]]+TABLE[[:space:]]+(IF[[:space:]]+NOT[[:space:]]+EXISTS[[:space:]]+)?(legal_consents|consent_log|consent_records|minor_consents)' \
  --include="*.sql"

# ── P. Password reset token safety ────────────────────────────────────────────
# P1: token compared with === (should be constant-time hash comparison)
check \
  "P1. Password-reset token compared with === - compare SHA-256 hashes with constant-time equality" \
  '(reset_token|resetToken|token)\s*===\s*(req\.|body\.|params\.|row\.)' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.mjs"

# P2: reset token redeemed without checking `used` flag
check \
  "P2. Password-reset token query without checking used=false (single-use not enforced)" \
  'password_reset_tokens|reset_tokens' \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.sql" --include="*.mjs" \
  | grep -v 'used' || true

_p2=$(grep -rnEi "${EXCLUDES[@]}" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.sql" --include="*.mjs" -- 'password_reset_tokens|reset_tokens' "$ROOT" 2>/dev/null | grep -v 'used' || true)
if [[ -n "$_p2" ]]; then
  printf '\n### P2. Password-reset token query without checking used=false\n%s\n' "$_p2"
  HITS=$(( HITS + 1 ))
fi

# ── Q. Supply chain ───────────────────────────────────────────────────────────
check \
  "Q. Unpinned Postgres / pgjdbc version (supply chain risk)" \
  'postgresql[^"'"'"']*latest|postgres[^"'"'"']*latest' \
  --include="*.yml" --include="*.yaml" --include="*.json" --include="*.toml"

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n=== Done: %d pattern group(s) matched ===\n' "$HITS"
if [[ "$HITS" -gt 0 ]]; then
  echo "Review each finding against:"
  echo "  .agents/skills/postgres-auth-security-review/references/checklist.md"
  exit 1
else
  echo "No matches for the patterns this script knows about."
  echo "That is not the same as a full security audit."
  exit 0
fi
