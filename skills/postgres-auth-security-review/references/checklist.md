# Postgres & Auth Security — Full Reference

Detailed reasoning, exact parameters, and full CVE records backing `SKILL.md`.
Researched against OWASP, NIST, PostgreSQL advisory pages, and published
incident reports. Current to mid-2026.

---

## 1. PostgreSQL version and patch status

**Safe minimums as of mid-2026**

| Branch | Minimum safe version | Key CVEs fixed |
|--------|---------------------|----------------|
| 14     | 14.23+              | CVE-2025-1094, CVE-2025-8714/15, CVE-2026-2004/5 |
| 15     | 15.18+              | same |
| 16     | 16.14+              | same |
| 17     | 17.10+              | same |
| 18     | 18.4+               | same |

Versions 12 and 13 reached end-of-life in November 2024. Do not run them.

### CVE-2025-1094 — psql SQL injection (CVSS 8.1)
`psql` mishandles invalid UTF-8 byte sequences in `PQescapeLiteral()` and
related libpq escape functions. An attacker who can inject input can escape
the quoting and reach raw SQL, then use psql's `\!` meta-command for OS
shell execution. Exploited in the December 2024 BeyondTrust breach chain
(US Treasury). Fixed in 17.3, 16.7, 15.11, 14.16, 13.19.

### CVE-2026-2004 / CVE-2026-2005 (CVSS 8.8)
`intarray` and `pgcrypto` extensions allow arbitrary code execution as the
OS user running the database, via crafted input to the selectivity estimator
and a heap buffer overflow respectively. Fixed in 18.2, 17.8, 16.12.

---

## 2. Row-Level Security — full failure taxonomy

### Off by default
`ENABLE ROW LEVEL SECURITY` must be applied explicitly to every table.
Supabase's dashboard began enabling it for UI-created tables in late 2025,
but SQL migrations, ORMs, and external tooling still skip it.

Verify with:
```sql
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
```

### USING (true) / WITH CHECK (true)
A policy evaluating `true` unconditionally is identical to no policy. These
are frequently created as scaffolding and never tightened.

### Partial operation coverage
`USING` governs `SELECT` and `DELETE`. `WITH CHECK` governs `INSERT` and
`UPDATE`. A policy providing only `USING` leaves writes completely unguarded.

### Table-owner bypass — the invisible one
Superusers, roles with `BYPASSRLS`, and the table owner all skip RLS unless
the table has `FORCE ROW LEVEL SECURITY`. Many ORMs and migration tools
connect as the table owner, making all policies silently ineffective.
```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoices
  USING (tenant_id = current_setting('app.tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```

### CVE-2024-10976 — query plan caching discards correct policy
When a plan is created under one role and re-executed under another (via
`SET ROLE`, `SECURITY DEFINER` functions, connection pool multiplexing,
subqueries, or security-invoker views), Postgres may apply the wrong policy.
Fixed in 17.1, 16.5, 15.9, 14.14, 13.17.

### Materialized views bypass RLS
Materialized views pre-aggregate data at refresh time. The RLS policies of
the underlying tables do not apply when the view is queried. Any role that
can `SELECT` from the view sees all rows in it, regardless of per-row
policies. Use materialized views only for non-sensitive aggregates, and grant
access only to the specific roles that need the aggregate data.

---

## 3. Custom RLS session-binding — worked example and failure modes

A common pattern in custom-auth stacks: the edge function extracts a JWT,
verifies it, then calls a PL/pgSQL RPC to set a session-level variable before
running queries. Example:
```sql
CREATE OR REPLACE FUNCTION public.set_current_user(p_uid uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM set_config('app.current_user_id', p_uid::text, true);  -- is_local=true
END;
$$;

CREATE OR REPLACE FUNCTION public.current_user_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT nullif(current_setting('app.current_user_id', true), '')::uuid;
$$;
```

**Failure mode 1 — fail-open policy:**
```sql
-- RISKY: if current_user_id() returns NULL, this may throw or behave
-- unpredictably depending on how NULL is handled in the comparison.
USING (public.current_user_id() = user_id)

-- SAFE: NULL = anything is NULL (falsy), so absent context = no rows.
-- This is actually safe as written because NULL != any uuid.
-- Explicitly document it as intentionally fail-closed.
```

**Failure mode 2 — is_admin() fails open:**
```sql
-- RISKY: returns true when session var absent or on any error
CREATE FUNCTION is_admin() RETURNS bool LANGUAGE plpgsql AS $$
BEGIN
  RETURN current_setting('app.role', true) = 'admin';
EXCEPTION WHEN OTHERS THEN
  RETURN true;  -- BUG: exception path grants admin to everyone
END;
$$;

-- SAFE: exception path fails closed
EXCEPTION WHEN OTHERS THEN
  RETURN false;
```

**Failure mode 3 — SET vs SET LOCAL:**
```sql
-- SET (session-scoped): variable persists even after the transaction ends.
-- In a connection pool, this leaks the user_id to the next request
-- served on the same connection.
SELECT set_config('app.current_user_id', uid, false);  -- false = session-scoped

-- SET LOCAL (transaction-scoped): automatically cleared at COMMIT/ROLLBACK.
-- Use this in connection-pooled environments.
SELECT set_config('app.current_user_id', uid, true);   -- true = transaction-scoped
```

**Failure mode 4 — RPC error not caught:**
If the call to `set_current_user()` throws an exception in the edge function
and the error is swallowed or causes an early return that skips the query,
the next call in the code may run queries without a set context. The query
will see RLS filter as `NULL = user_id` which returns no rows — which is
correct fail-closed behavior — but only if the query actually runs. If a
different code path bypasses the query and returns cached data, that cached
data may not be RLS-filtered.

---

## 4. SECURITY DEFINER and search_path

A `SECURITY DEFINER` function runs with the owner's privileges. Without a
locked `search_path`, an attacker who can create objects in any schema on
the search path can shadow trusted objects and run code with elevated
permissions.

The same root cause resurfaced in:
- **CVE-2018-1058** — PUBLIC CREATE + search_path shadowing
- **CVE-2020-14349** — logical replication left search_path unsanitized
- **CVE-2023-2454** — schema_element syntax bypassed hardening

Every SECURITY DEFINER function:
```sql
CREATE OR REPLACE FUNCTION secure_fn()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ BEGIN ... END; $$;
```

---

## 5. Password hashing — exact parameters

### Argon2id (preferred)
- Memory: ≥ 19 MiB (OWASP 2026 baseline), 64 MiB if server allows
- Iterations: ≥ 2
- Parallelism: ≥ 1 (match CPU threads available)
- Salt: library-generated per-password, 128 bits
- Output: ≥ 32 bytes

### bcrypt (acceptable for existing code)
- Cost ≥ 12. Cost 10 can be exhausted by a consumer GPU in days.
- Target ≥ 250 ms per hash on production hardware.
- Silently truncates at 72 bytes. Pre-hash with SHA-256 + base64 if the app
  accepts passphrases longer than 72 characters.

### Never use
`md5()`, `crypt()` with DES, `SHA-1`, `SHA-256` alone, or any unsalted hash.

---

## 6. Custom JWT with crypto.subtle — security requirements

### Why custom implementations exist
Serverless edge runtimes (Cloudflare Workers, Deno Deploy, etc.) often have
restricted environments where standard JWT libraries either don't run or add
significant bundle size. Rolling a custom HMAC-SHA256 JWT using the platform's
`crypto.subtle` API is a legitimate choice — but the library's guardrails are
gone, so you have to build them yourself.

### Algorithm pinning
```javascript
// WRONG — algorithm comes from the token header, enabling confusion attack
const { alg } = JSON.parse(atob(token.split('.')[0]));
const key = await crypto.subtle.importKey('raw', secret, { name: alg }, false, ['verify']);

// CORRECT — algorithm is pinned server-side, header value ignored
const ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };
const key = await crypto.subtle.importKey('raw', secret, ALGORITHM, false, ['verify']);
const valid = await crypto.subtle.verify(ALGORITHM, key, signature, data);
```

### alg:none rejection
```javascript
// Parse header BEFORE verifying signature
const header = JSON.parse(atob(parts[0]));
if (!header.alg || header.alg.toLowerCase() === 'none') {
  throw new Error('Invalid token: alg:none rejected');
}
```

### Claim verification order
1. `crypto.subtle.verify()` returns `true` — signature valid
2. Check `exp` > `Date.now() / 1000`
3. Check `nbf` ≤ `Date.now() / 1000` (if present)
4. Check `iat` is in a sane past range (reject future-dated tokens)
5. Now read `sub`, `role`, etc.

Reading claims before step 1 is a critical authentication bypass.

### Token lifetime
- Standard access tokens: ≤ 15 minutes.
- Session JWTs stored in httpOnly cookies: ≤ 24 hours is a practical
  maximum. Tokens with 7-day lifetimes (a common convenience default) create
  a long window during which a stolen token cannot be invalidated without
  rotating the signing secret (which logs out every user).
- Consider short-lived JWTs (≤ 1 hour) with a server-side session table for
  explicit revocation, rather than relying on expiry alone.

### HMAC secret requirements
- ≥ 256 bits (32 bytes) of cryptographically random entropy.
- Generated with `crypto.getRandomValues()` or equivalent, never with
  `Math.random()` or a human-readable passphrase.
- Stored in environment secrets, never in source code.
- Rotation invalidates all active tokens immediately — plan for it.

### Constant-time comparison
```javascript
// WRONG — timing side-channel: comparison short-circuits on first mismatch
if (computed === received) { ... }

// CORRECT — Web Crypto verify is constant-time by spec
const valid = await crypto.subtle.verify(ALGORITHM, key, receivedSig, data);

// If comparing byte arrays directly:
const encoder = new TextEncoder();
// Node.js:
import { timingSafeEqual } from 'node:crypto';
timingSafeEqual(encoder.encode(a), encoder.encode(b));
```

---

## 7. Serverless / edge function routing — failure modes

### Catch-all routing without a top-level auth guard
A pattern like:
```javascript
// functions/api/[[path]].js
export async function onRequest(context) {
  const path = context.params.path?.join('/') ?? '';
  if (path === 'login') return handleLogin(context);
  if (path === 'register') return handleRegister(context);
  // Auth check happens inside each handler below — RISKY
  if (path === 'profile') return handleProfile(context);
  if (path === 'documents') return handleDocuments(context);
}
```
A new handler added later may forget its auth check. Safer:
```javascript
const PUBLIC_ROUTES = new Set(['login', 'register', 'health']);
export async function onRequest(context) {
  const path = context.params.path?.join('/') ?? '';
  if (!PUBLIC_ROUTES.has(path)) {
    const user = await verifySession(context);
    if (!user) return new Response('Unauthorized', { status: 401 });
    context.user = user;
  }
  // dispatch
}
```

### Module-scope variable leakage between requests
```javascript
// WRONG — warm instances share module scope
let currentUser = null;
export async function onRequest(context) {
  currentUser = await getUser(context); // leaks to concurrent requests
}

// CORRECT — all state inside the handler
export async function onRequest(context) {
  const currentUser = await getUser(context);
}
```

### Path normalization
```javascript
// Normalize before dispatching
const safePath = new URL(request.url).pathname.replace(/^\/api\//, '');
// Reject traversal
if (safePath.includes('..') || safePath.includes('%2e%2e')) {
  return new Response('Bad Request', { status: 400 });
}
```

---

## 8. Object storage security (R2 / S3 / GCS)

### Object key design
```
// INSECURE — guessable, IDOR via log leak
users/{user_id}/{filename}

// SECURE — random prefix defeats directory traversal and enumeration
documents/{random_uuid}/{random_uuid}-{safe_filename}
```

### Pre-signed URL expiry
```javascript
// WRONG — no expiry
const url = await getSignedUrl(bucket, key);

// CORRECT — short expiry, server verifies ownership first
const doc = await db.query('SELECT object_key FROM documents WHERE id=$1 AND user_id=$2', [docId, userId]);
if (!doc) return new Response('Not found', { status: 404 });
const url = await getSignedUrl(bucket, doc.object_key, { expiresIn: 900 }); // 15 min
```

### CORS lockdown
```json
[{
  "AllowedOrigins": ["https://yourdomain.com"],
  "AllowedMethods": ["GET", "PUT"],
  "AllowedHeaders": ["Content-Type"],
  "MaxAgeSeconds": 3000
}]
```
Never `"AllowedOrigins": ["*"]` on a private bucket.

### Server-side file validation
```javascript
// Read magic bytes, not Content-Type header
const buffer = await file.arrayBuffer();
const bytes = new Uint8Array(buffer.slice(0, 8));
const isPDF = bytes[0] === 0x25 && bytes[1] === 0x50; // %P
if (!isPDF) return new Response('Invalid file type', { status: 415 });
if (buffer.byteLength > 10 * 1024 * 1024) return new Response('Too large', { status: 413 });
```

---

## 9. DB-backed rate limiting — atomic patterns

### IP source
```javascript
// WRONG — client-controlled header
const ip = request.headers.get('X-Forwarded-For');

// CORRECT — platform-verified header (Cloudflare)
const ip = request.headers.get('CF-Connecting-IP');
// nginx
const ip = request.headers.get('X-Real-IP');
```

### Atomic count-and-insert
```sql
-- Non-atomic (vulnerable to race condition):
SELECT count(*) FROM rate_limits WHERE ip=$1 AND endpoint=$2 AND created_at > now()-interval '1 min';
-- (race window here)
INSERT INTO rate_limits (ip_address, endpoint) VALUES ($1, $2);

-- Atomic alternative using advisory lock or INSERT with check:
WITH inserted AS (
  INSERT INTO rate_limits (ip_address, endpoint, created_at)
  VALUES ($1, $2, now())
  RETURNING id
),
recent AS (
  SELECT count(*) AS cnt FROM rate_limits
  WHERE ip_address=$1 AND endpoint=$2 AND created_at > now()-interval '1 min'
)
SELECT cnt FROM recent;
-- Then check cnt in application; rollback if over limit
```

### Per-account limiting
```javascript
// Add a separate counter keyed on email/username
// so distributed IPs targeting one account are still blocked
const [byIp, byEmail] = await Promise.all([
  countRecentAttempts({ ip, endpoint }),
  countRecentAttempts({ identifier: email, endpoint }),
]);
if (byIp >= 10 || byEmail >= 5) return tooManyRequests();
```

---

## 10. Password-reset token security

```sql
-- Schema: store hash, not raw token
CREATE TABLE password_reset_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,       -- SHA-256 of the raw token
  expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour',
  used       boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

```javascript
// Issue:
const rawToken = crypto.randomUUID() + crypto.randomUUID(); // 256 bits entropy
const tokenHash = await sha256hex(rawToken);
await db.query(
  'INSERT INTO password_reset_tokens (user_id, token_hash) VALUES ($1, $2)',
  [userId, tokenHash]
);
// Send rawToken to user's email only

// Redeem:
const tokenHash = await sha256hex(submittedToken);
const row = await db.query(
  `SELECT id, user_id FROM password_reset_tokens
   WHERE token_hash = $1
     AND expires_at > now()   -- expiry enforced at DB level
     AND used = false`,       -- single-use enforced at DB level
  [tokenHash]
);
if (!row) return invalid();

// Invalidate BEFORE using (prevents TOCTOU on concurrent redemptions)
await db.query('UPDATE password_reset_tokens SET used=true WHERE id=$1', [row.id]);
await resetPassword(row.user_id, newPasswordHash);
```

---

## 11. Minor / guardian consent — compliance checklist

Required fields for a legally defensible consent record:

```sql
CREATE TABLE legal_consents (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid REFERENCES users(id),
  consent_type        text NOT NULL,         -- 'minor_guardian', 'privacy_policy', etc.
  guardian_name       text,                  -- required when consent_type includes minor
  guardian_relation   text,
  policy_version      text NOT NULL,
  policy_url          text NOT NULL,
  consented_at        timestamptz NOT NULL DEFAULT now(),
  platform_ip         text NOT NULL,         -- CF-Connecting-IP, not X-Forwarded-For
  user_agent          text,
  -- Immutability: no UPDATE permitted via application role
  CONSTRAINT no_update CHECK (true)          -- enforced via RLS WITH CHECK
);

-- Prevent application role from modifying consent records
CREATE POLICY immutable_consents ON legal_consents
  FOR UPDATE USING (false)                   -- nobody can UPDATE via app role
  WITH CHECK (false);
```

Server-side age calculation:
```javascript
function getAgeYears(dob: string): number {
  const birth = new Date(dob);
  const now = new Date();
  let age = now.getFullYear() - birth.getFullYear();
  const beforeBirthday =
    now.getMonth() < birth.getMonth() ||
    (now.getMonth() === birth.getMonth() && now.getDate() < birth.getDate());
  if (beforeBirthday) age--;
  return age;
}

// Call server-side, never trust client-submitted age
if (getAgeYears(body.date_of_birth) < 18) {
  if (!body.guardian_name || !body.guardian_relationship) {
    return new Response('Guardian details required for minors', { status: 422 });
  }
}
```

---

## 12. OWASP Top 10:2025 mapping (updated for new sections)

| OWASP Category | Sections in this skill |
|---|---|
| A01 Broken Access Control | B (RLS), C (session binding), I (object storage IDOR), K (IDOR, mass assignment) |
| A02 Security Misconfiguration | B (RLS off), D (roles), H (catch-all routing), I (public bucket) |
| A03 Supply Chain | Unpatched Postgres, pgjdbc |
| A04 Cryptographic Failures | F (passwords), G (custom JWT), J (token security) |
| A05 Injection | E (SQL), H (path traversal) |
| A07 Authentication Failures | G (custom JWT), J (session fixation), K (CVE-2025-29927) |
| A08 Integrity Failures | K (webhooks), M (consent immutability) |
| A09 Logging Failures | L (rate-limit password logging risk), M (IP spoofing in logs) |

---

## 13. Full self-audit checklist (26 items)

### PostgreSQL version
1. Postgres ≥ 14.23 / 15.18 / 16.14 / 17.10 / 18.4
2. pgjdbc ≥ 42.7.7 if using JDBC

### Row-Level Security
3. RLS enabled on every user-data table (verify via `pg_tables` query)
4. `FORCE ROW LEVEL SECURITY` where app role owns the tables
5. Policies cover SELECT, INSERT, UPDATE, DELETE (both USING and WITH CHECK)
6. No `USING (true)` or `WITH CHECK (true)` policies
7. Materialized views containing user data restricted to specific roles
8. Postgres version patched for CVE-2024-10976

### Custom RLS session binding
9. Session-binding RPC uses `SET LOCAL` (is_local=true), not session-scoped SET
10. `is_admin()` and similar functions fail-closed on missing/error context
11. RPC error is caught; auth fails closed, not silently skipped

### Roles and SECURITY DEFINER
12. App role is least-privilege, not superuser, no BYPASSRLS
13. PUBLIC schema CREATE revoked
14. Every SECURITY DEFINER function has locked search_path

### SQL and queries
15. All queries parameterized (app and PL/pgSQL EXECUTE)

### Passwords and tokens
16. Passwords hashed with Argon2id or bcrypt ≥ cost 12
17. Reset tokens: hashed in DB, ≤ 1 hr expiry, single-use, 128+ bit random
18. Token comparisons use constant-time equality

### Custom JWT
19. Algorithm pinned at verify time; `alg: none` rejected
20. All three claims (exp, nbf, iat) verified before reading payload
21. HMAC secret ≥ 256 bits random, in env vars, not source code

### Serverless routing
22. Catch-all router has top-level auth guard with explicit public-route allowlist
23. No module-scope mutable state shared between requests

### Object storage
24. Bucket is private; object keys use random UUIDs, not user IDs
25. Pre-signed URLs have expiry ≤ 15 min; server checks ownership before issuing

### Rate limiting
26. Rate-limit IP sourced from platform-verified header (CF-Connecting-IP, X-Real-IP)
27. Count-check and insert are atomic; per-account limiting exists alongside per-IP

### Application
28. Age/minor check enforced server-side; consent records immutable
29. Password-reset `used` flag and expiry checked at DB level, not only in app code
30. `sslmode=require` everywhere; `service_role` keys absent from client bundles

---

## 14. Sources

- OWASP Top 10:2025 — owasp.org/Top10/2025
- OWASP Password Storage & Authentication Cheat Sheets — cheatsheetseries.owasp.org
- NIST SP 800-63B — pages.nist.gov/800-63-3/sp800-63b.html
- PostgreSQL Security Advisories — postgresql.org/support/security
  - CVE-2018-1058, CVE-2019-10130, CVE-2020-14349, CVE-2023-2454
  - CVE-2023-39417, CVE-2024-10976, CVE-2025-1094
  - CVE-2025-8714, CVE-2025-8715, CVE-2026-2004, CVE-2026-2005
- pgjdbc channel-binding bypass (2025-06-11) — github.com/pgjdbc/pgjdbc
- CVE-2025-29927 (Next.js middleware bypass) — projectdiscovery.io
- CVE-2025-48757 (Supabase/Lovable RLS exposure) — disclosed May 2025
- Supabase Security Retro 2025 — supabase.com/blog
- Web Crypto API specification — w3.org/TR/WebCryptoAPI
- Cloudflare Workers / Pages Functions runtime docs — developers.cloudflare.com
