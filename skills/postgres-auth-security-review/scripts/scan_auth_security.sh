#!/usr/bin/env bash
# scan_auth_security.sh: static grep scan for auth/Postgres/Supabase security
# red flags. Read-only: no network calls, no edits, no execution of repo code.
# Heuristic only: confirm every hit by hand.
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

echo "=== postgres-auth-security-review scanner v1.5.0 ==="
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

# F4: Long JWT expiry (> 24h): risky for stolen-token scenarios
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
# L1: set_config without is_local=true (session-scoped: leaks between pooled requests)
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

# ── Q. May 2026 PostgreSQL CVE batch ─────────────────────────────────────────
# Q1: pg_hba.conf using md5 auth method (CVE-2026-6478)
_q1=$(grep -rnEi "${EXCLUDES[@]}" --include="pg_hba.conf" --include="*.hba" --include="*.conf" -- '^[^#].*[[:space:]]md5[[:space:]]*$' "$ROOT" 2>/dev/null || true)
if [[ -n "$_q1" ]]; then
  printf '\n### Q1. pg_hba.conf md5 auth method: migrate to scram-sha-256 (CVE-2026-6478 timing attack)\n%s\n' "$_q1"
  HITS=$(( HITS + 1 ))
fi

# Q2: refint extension loaded (CVE-2026-6637: stack overflow + SQL injection)
_q2=$(grep -rnEi "${EXCLUDES[@]}" --include="*.sql" --include="*.sh" --include="*.py" -- 'CREATE[[:space:]]+EXTENSION.*refint|LOAD.*refint' "$ROOT" 2>/dev/null || true)
if [[ -n "$_q2" ]]; then
  printf '\n### Q2. contrib/refint loaded: drop it; replaced by native FK constraints (CVE-2026-6637 code execution)\n%s\n' "$_q2"
  HITS=$(( HITS + 1 ))
fi

# Q3: logical replication ALTER SUBSCRIPTION (CVE-2026-6638)
_q3=$(grep -rnEi "${EXCLUDES[@]}" --include="*.sql" --include="*.ts" --include="*.js" --include="*.py" -- 'ALTER[[:space:]]+SUBSCRIPTION.*REFRESH[[:space:]]+PUBLICATION' "$ROOT" 2>/dev/null || true)
if [[ -n "$_q3" ]]; then
  printf '\n### Q3. ALTER SUBSCRIPTION REFRESH PUBLICATION: verify names are quoted to prevent SQL injection (CVE-2026-6638)\n%s\n' "$_q3"
  HITS=$(( HITS + 1 ))
fi

# Q4: PQfn() usage: deprecated after CVE-2026-6477
_q4=$(grep -rnEi "${EXCLUDES[@]}" --include="*.c" --include="*.cpp" --include="*.h" -- '\bPQfn\s*\(' "$ROOT" 2>/dev/null || true)
if [[ -n "$_q4" ]]; then
  printf '\n### Q4. PQfn() used in libpq: deprecated (CVE-2026-6477); a hostile server can overwrite client stack memory\n%s\n' "$_q4"
  HITS=$(( HITS + 1 ))
fi

# Q5: Remind to audit pg_authid for MD5 hashes (always advisory)
printf '\n### Q5. MD5 password audit reminder (CVE-2026-6478)\n'
printf 'Run on every production cluster: SELECT rolname FROM pg_authid WHERE rolpassword LIKE '"'"'md5%%'"'"';\n'
printf 'Any results = legacy MD5 hash from pre-PG14 upgrade. Force password reset or ALTER ROLE ... WITH PASSWORD.\n'

# ── R. Supply chain ───────────────────────────────────────────────────────────

check \
  "R. Unpinned Postgres / pgjdbc version (supply chain risk)" \
  'postgresql[^"'"'"']*latest|postgres[^"'"'"']*latest' \
  --include="*.yml" --include="*.yaml" --include="*.json" --include="*.toml"


# -- S. Login and signup edge case patterns ----------------------------------
# S1: Different error messages for "user not found" vs "wrong password" (enumeration)
_s1=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -- '(no account|account not found|user not found|email not found|not registered|no user found)' \
  "$ROOT" 2>/dev/null || true)
if [[ -n "$_s1" ]]; then
  printf '\n### S1. Specific "not found" error message - reveals account existence to attackers (enumeration risk)\n%s\n' "$_s1"
  HITS=$(( HITS + 1 ))
fi

# S2: Password reset revealing email existence ("email sent" vs "no account" branch)
_s2=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -- '(email|account).*(not found|does not exist|not registered)' \
  "$ROOT" 2>/dev/null | grep -i 'reset\|password\|forgot' || true)
if [[ -n "$_s2" ]]; then
  printf '\n### S2. Password reset reveals whether email is registered - use "if account exists, email sent"\n%s\n' "$_s2"
  HITS=$(( HITS + 1 ))
fi

# S3: Login handler missing dummy hash comparison for timing defense
_s3=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -- '(login|signin|authenticate)' \
  "$ROOT" 2>/dev/null | grep -i 'not found\|no user\|null\|undefined' | grep -v 'dummy\|bcrypt\|argon\|compare\|verify' || true)
if [[ -n "$_s3" ]]; then
  printf '\n### S3. Login early-return when user not found without dummy hash comparison - timing side-channel\n%s\n' "$_s3"
  HITS=$(( HITS + 1 ))
fi

# S4: Password reset token not invalidated before changing password (TOCTOU)
_s4=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.sql" \
  -- 'UPDATE.*password|resetPassword|updatePassword' \
  "$ROOT" 2>/dev/null | grep -v 'used.*true\|invalidate\|expire\|transaction\|BEGIN' || true)
if [[ -n "$_s4" ]]; then
  printf '\n### S4. Password change without visible token invalidation - confirm token is marked used before password update\n%s\n' "$_s4"
  HITS=$(( HITS + 1 ))
fi

# S5: Account lockout only on IP, not on email/username identifier
_s5=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -- '(rate.?limit|lockout|failed.?attempt)' \
  "$ROOT" 2>/dev/null | grep -i 'ip\|address' | grep -iv 'email\|username\|identifier\|user.?id' || true)
if [[ -n "$_s5" ]]; then
  printf '\n### S5. Lockout/rate-limit keyed only on IP - also lock on email/username to stop distributed attacks\n%s\n' "$_s5"
  HITS=$(( HITS + 1 ))
fi

# S6: Session not regenerated after login (session fixation)
_s6=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -- '(session\.(save|set)|setSession|createSession)' \
  "$ROOT" 2>/dev/null | grep -iv 'regenerate\|rotate\|new.*session\|create.*session' || true)
if [[ -n "$_s6" ]]; then
  printf '\n### S6. Session saved/set without regeneration - regenerate session ID after successful login to prevent fixation\n%s\n' "$_s6"
  HITS=$(( HITS + 1 ))
fi

# ── Summary ───────────────────────────────────────────────────────────────────

# -- T. RLS drift and unsafe execution paths (PreFlight-class checks) ---------
# T1: supabaseAdmin / service role client used in a user-facing route mutation
_t1=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -- 'supabaseAdmin|supabase_admin|serviceRoleClient|service_role_client' \
  "$ROOT" 2>/dev/null | grep -Ei '\.(from|rpc|storage)\(' | grep -Ei '\.update|\.delete|\.insert|\.upsert' || true)
if [[ -n "$_t1" ]]; then
  printf '\n### T1. supabaseAdmin/service-role client used for a mutation (bypasses all RLS - confirm this is intentional)\n%s\n' "$_t1"
  HITS=$(( HITS + 1 ))
fi

# T2: UPDATE or DELETE without explicit ownership filter (hallucinated mutation / IDOR)
_t2=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -- '\.update\(|\.delete\(' \
  "$ROOT" 2>/dev/null | grep -v 'user_id\|userId\|owner_id\|ownerId\|tenant_id\|tenantId\|current_user_id\|supabaseAdmin\|supabase_admin' || true)
if [[ -n "$_t2" ]]; then
  printf '\n### T2. Mutation without visible ownership filter - confirm this is not an IDOR (missing user_id/tenant_id filter)\n%s\n' "$_t2"
  HITS=$(( HITS + 1 ))
fi

# T3: COPY TO PROGRAM or COPY FROM PROGRAM in SQL (OS command execution)
_t3=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.sql" --include="*.ts" --include="*.js" --include="*.py" \
  -- 'COPY[[:space:]].*TO[[:space:]]+PROGRAM|COPY[[:space:]].*FROM[[:space:]]+PROGRAM' \
  "$ROOT" 2>/dev/null || true)
if [[ -n "$_t3" ]]; then
  printf '\n### T3. COPY TO/FROM PROGRAM detected - OS command execution from PostgreSQL (revoke pg_execute_server_program)\n%s\n' "$_t3"
  HITS=$(( HITS + 1 ))
fi

# T4: pg_read_file / pg_write_file / pg_ls_dir usage (server file system access)
_t4=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.sql" --include="*.ts" --include="*.js" --include="*.py" \
  -- 'pg_read_file|pg_write_file|pg_ls_dir|pg_read_binary_file' \
  "$ROOT" 2>/dev/null || true)
if [[ -n "$_t4" ]]; then
  printf '\n### T4. pg_read_file/pg_write_file/pg_ls_dir usage - server file system access from SQL\n%s\n' "$_t4"
  HITS=$(( HITS + 1 ))
fi

# T5: lo_import / lo_export / lo_from_bytea in SECURITY DEFINER functions (file I/O via large objects)
_t5=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.sql" \
  -- 'lo_import|lo_export|lo_from_bytea|lo_get|lo_put' \
  "$ROOT" 2>/dev/null || true)
if [[ -n "$_t5" ]]; then
  printf '\n### T5. lo_import/lo_export/lo_from_bytea usage - file I/O via PostgreSQL large objects (check SECURITY DEFINER context)\n%s\n' "$_t5"
  HITS=$(( HITS + 1 ))
fi

# T6: exec() or execSync() in server code (shell injection risk)
_t6=$(grep -rnEi "${EXCLUDES[@]}" \
  --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.mjs" \
  -- '\bexec\s*\(|\bexecSync\s*\(' \
  "$ROOT" 2>/dev/null | grep -v 'execFile\|execSync.*\[' || true)
if [[ -n "$_t6" ]]; then
  printf '\n### T6. exec()/execSync() in server code - use execFile() with an argument array instead (shell injection risk)\n%s\n' "$_t6"
  HITS=$(( HITS + 1 ))
fi

# T7 removed - covered by B3 (CREATE TABLE without ENABLE ROW LEVEL SECURITY)

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
