---
name: postgres-auth-security-review
description: Reviews and writes authentication, session-management, and PostgreSQL/Supabase database-access code for common and uncommon security mistakes before it ships. Trigger on login/signup/password-reset flows, JWT or session/cookie handling, SQL queries and migrations, RLS policies, SECURITY DEFINER functions, Postgres roles/grants, Supabase client/key usage, custom JWT implementations (crypto.subtle/HMAC), serverless/edge function routing, object storage (R2/S3/GCS), DB-backed rate limiting, or minor/guardian consent flows. Do not trigger for unrelated UI, styling, or business logic with no auth or database-access surface.
license: MIT
compatibility: Works with any agent that supports the agentskills.io standard (Codex CLI, Antigravity, Claude Code, Cursor, Gemini CLI, GitHub Copilot). Scan script requires bash and grep.
metadata:
  author: maherukhislam
  version: "1.5.0"
  tags: security postgres supabase authentication rls jwt cve cloudflare r2 edge serverless custom-jwt
  references: OWASP Top 10:2025, NIST SP 800-63B, CVE-2025-1094, CVE-2025-29927, CVE-2025-48757, CVE-2024-10976, CVE-2026-2004, CVE-2026-2005, CVE-2026-6472, CVE-2026-6473, CVE-2026-6475, CVE-2026-6477, CVE-2026-6478, CVE-2026-6479, CVE-2026-6637, CVE-2026-6638
---

# Postgres & Auth Security Review

Apply this skill whenever a task touches login, sessions, password storage,
JWTs, SQL queries, migrations, RLS policies, Postgres/Supabase credentials,
custom JWT signing (crypto.subtle / HMAC), serverless edge routing, object
storage (R2/S3/GCS), DB-backed rate limiting, or minor/guardian consent flows.
Work through every applicable section before marking the task done. Fix inline
where possible. Flag what you cannot fix yourself and explain why.

Full reasoning, CVE case studies, and exact parameters are in
`references/checklist.md`. Run the static scanner with:
`scripts/scan_auth_security.sh [path]`

---

## A. PostgreSQL version & patch status

- **Run supported, patched Postgres.** As of June 2026, safe minimums are
  14.23+, 15.18+, 16.14+, 17.10+, or 18.4+. **PostgreSQL 14 reaches
  end-of-life on November 12, 2026** - begin migration to 16 or 17 now.
- **May 2026 release (18.4 / 17.10 / 16.14 / 15.18 / 14.23):** The largest
  single-batch security release in PostgreSQL's history fixed 11 CVEs. Patch
  immediately - three are CVSS 8.8 with practical exploit paths.
- **CVE-2026-6473 (CVSS 8.8):** Integer wraparound in server memory-allocation
  calculations allows an application-input provider to trigger an out-of-bounds
  write and crash or compromise the backend. Also affects `intarray` and
  `ltree` extension parsing. Fixed in 18.4, 17.10, 16.14, 15.18, 14.23.
- **CVE-2026-6475 (CVSS 8.8):** Path traversal in `pg_basebackup` and
  `pg_rewind` via symlink following. OS account hijack on the client running
  the backup tool. Fixed in 18.4, 17.10, 16.14, 15.18, 14.23.
- **CVE-2026-6477 (CVSS 8.8):** `PQfn()` in libpq is not passed an output
  buffer size. A malicious server superuser can overwrite client stack memory
  via `lo_export()`, `lo_read()`, `pg_dump`. Fixed in 18.4, 17.10, 16.14,
  15.18, 14.23.
- **CVE-2026-6472 (CVSS 5.4):** `CREATE TYPE` does not check `CREATE`
  privilege on the target schema, allowing an object creator to shadow
  extension-defined types and hijack `search_path` queries - same class as
  CVE-2018-1058. Fixed in 18.4, 17.10, 16.14, 15.18, 14.23.
- **CVE-2026-6478 (CVSS 6.5):** Covert timing channel in MD5 password
  comparison during authentication. An attacker with repeated connection
  access can incrementally recover credentials. **SCRAM-SHA-256 is immune.**
  Only affects clusters with MD5 password hashes remaining from upgrades of
  PostgreSQL 13 or earlier. Run `SELECT rolname FROM pg_authid WHERE
  rolpassword LIKE 'md5%';` - if it returns rows, migrate those passwords
  to SCRAM. Fixed in 18.4, 17.10, 16.14, 15.18, 14.23.
- **CVE-2026-6479 (CVSS 7.5):** Uncontrolled recursion in SSL/GSS startup
  negotiation. An unauthenticated client can crash the PostgreSQL backend
  by alternating rejected SSL/GSS requests. Affects any instance reachable
  by untrusted clients. Fixed in 18.4, 17.10, 16.14, 15.18, 14.23.
- **CVE-2026-6638 (CVSS 3.7):** SQL injection in `ALTER SUBSCRIPTION …
  REFRESH PUBLICATION` via unquoted table names. Fires on the publisher at
  next refresh - relevant for multi-tenant or federated logical replication
  setups. Fixed in 18.4, 17.10, 16.14 (affects v16+).
- **CVE-2026-6637 (CVSS TBD):** Stack buffer overflow plus SQL injection in
  `contrib/spi` (`refint` module). Any deployment with `refint` loaded is
  vulnerable to code execution by an unprivileged DB user. Drop `refint` -
  it was obsoleted by native foreign keys decades ago.
- **CVE-2025-1094 (CVSS 8.1):** psql SQL injection via invalid UTF-8 in
  `PQescapeLiteral()`. Exploited in the 2024 US Treasury breach chain.
  Fixed in 17.3, 16.7, 15.11, 14.16, 13.19.
- **CVE-2026-2004 / CVE-2026-2005 (CVSS 8.8):** `intarray` and `pgcrypto`
  extension arbitrary code execution. Fixed in 18.2, 17.8, 16.12.
- **CVE-2025-8714 / CVE-2025-8715:** `pg_dump` object-name injection.
  Fixed in 17.6, 16.10, 15.14, 14.19, 13.22.
- **pgjdbc channel-binding bypass (CVSS 8.2):** Versions 42.7.4-42.7.6
  silently downgrade auth. Upgrade to pgjdbc 42.7.7+.
- **pg_hba.conf auth method:** Any connection entry still using `md5` is
  vulnerable to CVE-2026-6478. Change to `scram-sha-256`. This is the
  default since PostgreSQL 14 but legacy clusters upgraded from PG13 may
  still have `md5` entries.
- Flag any Dockerfile, manifest, or connection string below these minimums.

---

## B. Row-Level Security: the #1 failure class

- Every user-data table needs `ENABLE ROW LEVEL SECURITY`. RLS is off by
  default; Supabase dashboard enables it for new tables created via the UI
  since late 2025, but SQL migrations and ORMs do not.
- Policies must cover all four operations. `USING` governs `SELECT`/`DELETE`;
  `WITH CHECK` governs `INSERT`/`UPDATE`. A policy with only one does not
  protect the other.
- Never leave `USING (true)` or `WITH CHECK (true)` as a placeholder.
- `ALTER TABLE t FORCE ROW LEVEL SECURITY` is required when the app's
  connecting role owns the tables it queries (common with ORMs and migration
  tools). Without it, the owner bypasses every policy silently.
- **CVE-2024-10976:** Query plan caching can apply the wrong RLS policy when
  a plan is created under one role and reused under another via `SET ROLE` or
  a `SECURITY DEFINER` function. Fixed in 17.1, 16.5, 15.9, 14.14, 13.17.
- Supabase Storage buckets are a separate RLS surface - `storage.objects`
  needs its own policies exactly like tables.
- Test RLS as a non-owner, non-superuser role. Testing as the table owner
  means policies are never applied.

---

## C. Custom RLS session-binding functions

Many stacks avoid the Supabase GoTrue auth flow and instead set a
session-level variable at the start of each request to bind the RLS context
(e.g., calling a PL/pgSQL function like `set_current_user(uid)` before
running queries). This pattern is valid but carries specific failure modes:

- **Fail-open on RPC error:** If the RPC that sets the session variable
  throws or is skipped due to an early return, the subsequent queries run
  without an RLS context. The RLS policy must be written to fail-closed
  (return no rows / deny writes) when the session variable is absent - not
  just when it is set to the wrong value.
  ```sql
  -- SAFE: fails closed when variable is not set
  USING (public.current_user_id() = user_id)

  -- RISKY: may return true or error unpredictably if variable absent
  USING (current_setting('app.user_id', true)::uuid = user_id)
  ```
- **Admin bypass must be explicit and narrow:** If `is_admin()` or an
  equivalent function grants full table access, verify it reads from the
  same session variable - not a hard-coded role name or a table the
  attacker can influence. `is_admin()` must also fail-closed when the
  session context is missing, not return `true` by default.
- **Single connection per request:** Connection pools that multiplex multiple
  users over one Postgres connection can leak session variables between
  requests. Ensure each request runs inside its own transaction scope, or use
  `SET LOCAL` (transaction-scoped) rather than `SET` (session-scoped) when
  binding the user context.
  ```sql
  -- Prefer SET LOCAL so context is automatically cleared at transaction end
  SELECT set_config('app.user_id', $1, true);  -- third arg = is_local = true
  ```
- **`SECURITY DEFINER` + search_path:** The function that sets the session
  variable is almost certainly `SECURITY DEFINER`. Pin its `search_path`
  (see section E).
- **Materialized views bypass row security.** A materialized view
  pre-aggregates data at refresh time, outside any per-request RLS context.
  Any role that can query the view can see all rows it contains, regardless
  of what the underlying table's policies say. If a materialized view
  contains user-specific data, treat its access as a separate authorization
  surface: restrict `SELECT` with explicit role grants, or refresh it only
  for non-sensitive aggregates.

---

## D. Roles, privileges, and SECURITY DEFINER

- App connects with a least-privilege role, not the `postgres` superuser.
- Revoke `CREATE` from `PUBLIC` on the `public` schema (default before
  Postgres 15). Closes the mechanism behind CVE-2018-1058 and reintroductions
  in CVE-2020-14349 and CVE-2023-2454.
- Every `SECURITY DEFINER` function must `SET search_path = pg_catalog, public`
  in its definition. An unlocked `search_path` allows schema-shadowing attacks.
- Do not grant `BYPASSRLS` or `SUPERUSER` to application roles.

---

## E. SQL injection: application and database layers

- Parameterize all queries. `$1, $2, ...` in Postgres; ORM-bound elsewhere.
  No string concatenation anywhere.
- Inside `PL/pgSQL`, `EXECUTE format('...', ...)` with `%I`/`%L` is correct.
  `EXECUTE 'SELECT … ' || input` is injection.
- **CVE-2025-1094:** `PQescapeLiteral()` and related libpq escape functions
  mishandle invalid UTF-8, allowing injection. Use parameterized binding.
- Extension scripts with `@extschema@` substitutions are vulnerable to
  injection by privileged roles (CVE-2023-39417). Audit custom extensions.

---

## F. Password hashing

- **Argon2id** for all new code: memory ≥ 19 MiB, iterations ≥ 2,
  parallelism ≥ 1.
- **bcrypt** for existing codebases: cost factor ≥ 12. bcrypt silently
  truncates at 72 bytes - pre-hash long passphrases with SHA-256.
- Never `md5()`, `crypt()`, `SHA-256 alone`, or any fast hash for passwords.
- Never hash inside SQL. Hash at the application layer.
- NIST SP 800-63B: 8 chars min with MFA, 15 without. Accept up to 64.

---

## G. Custom JWT implementations (crypto.subtle / server-side HMAC)

Many serverless and edge stacks implement JWT signing and verification
manually using `crypto.subtle` or a similar low-level API instead of a
standard JWT library. This is valid but requires strict discipline:

- **Pin the algorithm explicitly on both sign and verify.** Pass the exact
  algorithm object (e.g., `{ name: "HMAC", hash: "SHA-256" }`) to every
  `crypto.subtle.sign()` and `crypto.subtle.verify()` call. If the verify
  path accepts a header-derived algorithm, it is an algorithm-confusion
  vulnerability exactly as it would be with a JWT library.
- **Reject `alg: none` explicitly.** Parse the header and abort if `alg` is
  any case variant of `"none"` before touching `crypto.subtle.verify()`.
- **Verify before trusting any claim.** The token header and payload are
  base64-decoded, not validated, until `crypto.subtle.verify()` returns
  `true`. Never read `payload.sub` or `payload.role` before the signature is
  confirmed.
- **Token lifetime must be enforced at verification time:**
  - For standard access tokens ≤ 15 minutes.
  - For session cookies shared as JWTs, ≤ 24 hours is a reasonable maximum;
    7-day expiry with no refresh rotation is risky if a token is stolen.
  - Check `exp` (expiry), `nbf` (not-before), and `iat` (issued-at) against
    the current clock on every verify.
- **HMAC secret rotation:** The secret used to sign tokens must be ≥ 256 bits
  of cryptographically random entropy, stored in environment variables, never
  in source code, and rotated whenever exposure is suspected. A rotated secret
  immediately invalidates all current sessions - plan for graceful re-login.
- **Use constant-time comparison for token equality checks.** Any place in
  the code that compares a token, token hash, or HMAC output with `===` or
  `==` is vulnerable to timing attacks. Use `crypto.timingSafeEqual()` (Node)
  or `crypto.subtle.verify()` (Web Crypto API) instead.

---

## H. Serverless / edge function routing security

Catch-all serverless routers (e.g., Cloudflare Pages Functions
`[[path]].js`, Vercel `[...slug].ts`, AWS Lambda proxy) are convenient but
create specific failure modes:

- **Auth must run before the route dispatcher, not inside each handler.**
  A catch-all that checks auth at the top of a switch/if-else risks a new
  route branch being added and silently bypassing the auth check. Enforce
  auth as a middleware-layer guard that wraps every handler, with an explicit
  allowlist of unauthenticated routes (`/login`, `/register`, `/health`).
- **`nodejs_compat` / edge runtime differences:** Edge runtimes may not
  support all Node.js crypto primitives. Test that `crypto.subtle`,
  `crypto.timingSafeEqual`, and any hash function used in auth work correctly
  in the target runtime - fallbacks to `Math.random()` or non-crypto APIs
  are bugs, not degraded-mode behavior.
- **No shared mutable state between requests.** Serverless functions can have
  warm instances that serve multiple sequential requests. A variable declared
  at module scope (outside the handler function) can leak data between users.
  Keep all per-request state inside the handler function.
- **Route path validation:** A catch-all router receiving `/api/../../secret`
  or similar path traversal patterns must normalize and validate the path
  before dispatching. Never pass the raw URL path directly to a filesystem
  read or a template lookup.
- **Error responses must not leak internals.** Stack traces, SQL error
  messages, and connection strings in error responses are significant in
  serverless environments where the same function handles authenticated and
  unauthenticated paths.

---

## I. Object storage security (R2 / S3 / GCS)

Applications that store sensitive files (documents, certificates, passports)
in object storage have a surface area that RLS does not cover:

- **Bucket must be private.** Never configure a bucket holding sensitive
  documents as public - not even "public with signed URLs required." A public
  bucket means any URL that leaks (logs, referrer headers, share-link misuse)
  gives unauthenticated access.
- **Object keys must not be guessable.** A key like
  `users/1042/passport.pdf` is an IDOR waiting for a directory-listing bug
  or a log leak. Use UUIDs or cryptographically random prefixes as object
  keys, not user IDs or sequential numbers.
- **Pre-signed URLs must have short expiry.** ≤ 15 minutes for
  download links shown to users. ≤ 5 minutes for upload URLs. Never issue
  permanent pre-signed URLs.
- **Validate MIME type and file size on upload, server-side.** Client-side
  checks are trivially bypassed. Re-validate on the server using the actual
  bytes (magic-byte check), not the `Content-Type` header the client sends.
- **CORS policy must be restrictive.** Allow only the application's own
  origin. A wildcard CORS policy on a private bucket lets attacker-controlled
  pages make credentialed requests using a victim's pre-signed URL.
- **Object key ownership must be checked before issuing a signed URL.**
  When a user requests a download link, the API must verify that the
  `object_key` belongs to the requesting user's records before calling the
  storage SDK - not just verify the JWT. This is IDOR at the storage layer.
- **Delete alongside DB rows.** When a document record is deleted from the
  database, the corresponding object in storage must be deleted too, or
  storage becomes an orphaned data leak.

---

## J. JWT and token security (standard libraries)

- **Algorithm allowlist:** Verify with an explicit `algorithms: ["RS256"]`
  (or whichever algorithm the system uses) server-side. Never trust the `alg`
  field from the token header.
- Reject `alg: none` and all case variants (`nOnE`, `NONE`).
- **Supabase 2025/2026 key changes:** `service_role` bypasses all RLS - keep
  server-only. Supabase now auto-revokes secret keys detected in public repos.
- Short token lifetimes. Access tokens ≤ 15 minutes; refresh tokens rotated
  on use and invalidated on logout.
- Store session tokens in `httpOnly` + `Secure` + `SameSite=Strict` cookies,
  not `localStorage` or `sessionStorage`.
- **Session fixation:** Regenerate the session identifier (issue a new cookie
  value) after every successful login.

---

## K. Application authentication patterns

- Rate-limit login, signup, and password-reset per IP and per account.
- Error messages and response timing must not reveal whether an email exists.
- Authorization checks ownership (`record.user_id == current_user.id`), not
  just authentication. Checking only "is logged in" before returning
  `/resource/:id` is an IDOR.
- Never blindly map request body fields onto a DB model (mass assignment).
- Password-reset and email-verification tokens: ≤ 1 hour expiry, single-use
  (invalidate immediately on first use), ≥ 128 bits of random entropy.
  Store the hash, not the raw token. Compare with constant-time equality.
- Webhook endpoints verify the payload signature before processing.
- OAuth flows must use `state` (CSRF token) and PKCE
  (`code_challenge`/`code_verifier`).
- **CVE-2025-29927 (CVSS 9.1): Next.js middleware bypass.** Sending
  `x-middleware-subrequest` bypasses all Next.js Middleware on self-hosted
  deployments < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3. Upgrade immediately.
  Always validate sessions/JWTs in the API route or action itself too.

---

## L. DB-backed rate limiting pitfalls

Implementing rate limiting with a database table (logging attempts, counting
by IP, pruning old rows) is a valid pattern for serverless environments, but
has several failure modes:

- **IP spoofing via X-Forwarded-For.** Never use the raw
  `X-Forwarded-For` header as the rate-limit key. On most CDN/edge platforms,
  the real client IP is in a platform-specific header (`CF-Connecting-IP` on
  Cloudflare, `X-Real-IP` on nginx, etc.). Using `X-Forwarded-For` directly
  lets a client set their own IP by including the header.
- **Race condition on count-then-insert.** A check-then-act pattern
  (`SELECT count → decide → INSERT`) is not atomic. Under concurrent requests
  the count check can pass for multiple requests before any of them have
  inserted, admitting more attempts than intended. Mitigate with a DB-level
  unique constraint or a single atomic upsert (`INSERT … ON CONFLICT`).
- **Apply rate limiting per account too, not only per IP.** IP-only limiting
  is bypassed trivially from a residential proxy pool. Add a separate per-
  user-identifier (email/username) counter so credential stuffing at scale
  is blocked even from fresh IPs.
- **Async pruning is not guaranteed.** Randomly deleting old rows works at
  scale but means the table can grow unbounded if the pruning path is never
  hit. Add a cron job or a `pg_cron` scheduled task as a guaranteed cleanup
  path, so the table doesn't become a DoS vector against the DB itself.
- **Do not log plaintext passwords into the rate-limit table.** If the
  endpoint accidentally stores any request parameter in the `rate_limits`
  table (e.g., for debugging), and the endpoint is the login form, you are
  logging passwords.

---

## M. Minor / guardian consent flows

Applications that collect data from or provide services to minors require
additional checks that are easy to break:

- **Age verification must happen server-side.** A client-side age check is
  bypassed by editing the request. The server must calculate age from the
  submitted date-of-birth and enforce the restriction independently of
  anything the client claims.
- **Guardian consent must be stored with the consent record, not just
  checked as a boolean flag.** The specific guardian's name, relationship,
  and the consent event (timestamp, IP, user-agent, policy version) must be
  archived. A boolean `has_guardian_consent = true` without the supporting
  record has no legal or audit value.
- **Consent records must be immutable.** Write guardian and legal consent
  records with no `UPDATE` path - only `INSERT`. Add an RLS `WITH CHECK`
  policy that prevents the application role from modifying them after the
  fact. An attacker who compromises an account should not be able to
  retroactively forge consent.
- **IP and user-agent in consent records are advisory only.** `X-Forwarded-For`
  can be spoofed (see section L). Log the platform-verified client IP, not the
  header value, and label the field accordingly.
- **Notify the guardian, not just the applicant.** Consent is not meaningful
  if the only notification goes to the person being consented for. Send
  confirmation to the guardian's contact method.
- **Age re-verification on sensitive updates.** If a user can change their
  date-of-birth after registration, the system must re-evaluate minor status
  and re-request guardian consent if the new date makes them a minor. Allow
  date-of-birth changes only through an admin-mediated flow.

---

## N. Network and secret hygiene

- `sslmode=require` (or `verify-full`) on every connection string.
  `sslmode=disable` is never acceptable.
- Port 5432 and pooler ports must not be open to the public internet.
- `service_role` / secret keys must never appear in `NEXT_PUBLIC_` env vars,
  client components, browser bundles, git history, or error responses.
- Secrets are rotated after any suspected exposure. Deleting from git history
  does not remove from clone history - rotation is mandatory.
- Disable the Supabase Data API (auto-generated REST/GraphQL) if the app uses
  direct DB connections; reduces the public attack surface.

---

## O. Before marking done: final scan gate

Run `scripts/scan_auth_security.sh` on the diff and clear every finding.
Minimum checks:

1. `USING (true)` / `WITH CHECK (true)` in any RLS policy
2. `service_role` key outside server-only path
3. `sslmode=disable` in any connection string
4. String-concatenated SQL anywhere (app and PL/pgSQL layers)
5. `md5(` / `crypt(` near password handling
6. New table with no RLS migration
7. JWT verify without explicit algorithm allowlist
8. `x-middleware-subrequest` not stripped (Next.js stacks)
9. `NEXT_PUBLIC_` prefixed secret/service-role key
10. Postgres version below mid-2026 patched minimums
11. `crypto.subtle.verify()` / custom HMAC verify without `alg: none` rejection
12. Object key constructed from a user-supplied ID (IDOR at storage layer)
13. Pre-signed URL with no expiry parameter
14. Rate-limit IP read from raw `X-Forwarded-For`
15. `===` used to compare tokens or HMAC outputs (timing-attack surface)
16. Catch-all route handler without a top-level auth guard
17. `set_current_user` / session-binding RPC call without error handling
18. Materialized view containing user-specific data with no access restriction
19. Age/minor check present only in client-side code
20. `used` flag or expiry not checked on password-reset token redemption

---

## P. Engineering trade-offs: security without killing performance

Security and performance are not opposites. Most security slowdowns are
symptoms of a wrong implementation, not an inherent cost of the control
itself. This section gives you the right implementation so you don't have to
choose.

### P1. Password hashing: match the algorithm to the runtime

The deliberate slowness of bcrypt and Argon2id is the security feature.
An attacker who steals your database hash file faces the same cost per guess
that you face on login - but your users log in once; the attacker has to try
millions. Do not weaken the cost factor to gain speed. Find the right runtime.

**The problem on edge workers:** Pure JavaScript implementations of Argon2id
consume ~14,000ms CPU time per hash in a V8 isolate. Pure JavaScript bcrypt
runs ~2,000ms. <cite index="2-1">On Cloudflare Workers' free tier the CPU limit is 10ms, making
pure-JS Argon2id completely unusable.</cite> Even on the paid tier, <cite index="4-1">a bcrypt
cost-12 hash taking 250ms means a single core does about 4 logins per second
before requests queue</cite> - a login-spike DoS from the hash function itself.

**The correct architectural response:**
- **Separate the hashing.** Move password hashing out of the main edge function
  into a dedicated backend service with proper CPU resources. On Cloudflare
  this is a Rust-based Worker accessed via <cite index="2-1">a Cloudflare Service Binding,
  achieving ~100ms CPU time - the same Argon2id security at a practical cost</cite>.
  On other stacks, use a queue (send hash job, return token, confirm later) or
  a traditional server endpoint that the edge function delegates to.
- **Never weaken the algorithm as a "fix" for edge performance.** If you
  cannot run bcrypt cost 12 on your runtime, the answer is to change the
  runtime or add a dedicated service - not to drop to cost 8.
- **Always use the async API.** Synchronous bcrypt (`bcrypt.hashSync`)
  blocks the entire event loop and kills concurrency for all users. Always
  use `bcrypt.hash()` / `argon2.hash()` (async).
- **Bound the worker pool.** <cite index="4-1">Once arrival rate exceeds service rate, queue
  wait time grows without bound.</cite> Put the hashing endpoint behind a queue or
  semaphore so a login spike doesn't cascade into a DoS across the whole API.
- **Calibrate to your hardware.** <cite index="4-1">The same cost factor can take 60ms on one
  CPU and 250ms on another.</cite> Benchmark on production hardware. The target
  is ≥ 200ms per hash at the cost factor you choose.

### P2. Row-Level Security: the performance issue is almost always a missing index

RLS itself is not slow. <cite index="15-1">At 100K rows with no index, RLS adds ~1.6ms of
overhead on a count query - less than 2% difference from no RLS.</cite>
The performance cliff people hit is a sequential scan caused by a missing
index on the column used in the policy predicate.

**The single most important optimization: index every RLS predicate column.**
<cite index="12-1">For a policy like `USING (user_id = current_user_id())`, adding a
B-tree index on `user_id` has been seen to give over 100× improvement on large
tables.</cite> <cite index="15-1">Adding that index drops the same count query from ~73ms to
~2.2ms - a 26× speedup - while RLS overhead within the indexed condition
stays below 25%.</cite>

```sql
-- For every RLS predicate column, add an index:
CREATE INDEX idx_invoices_user_id ON invoices USING btree (user_id);
CREATE INDEX idx_documents_user_id ON documents USING btree (user_id);
-- For queries that filter on user_id + status, a composite index:
CREATE INDEX idx_documents_user_status ON documents (user_id, status);
```

**Wrap session-context functions in `(SELECT ...)`** to allow Postgres to
cache the result once per transaction instead of re-evaluating it for every
row scanned:

```sql
-- SLOW: current_user_id() is called once per row
USING (public.current_user_id() = user_id)

-- FAST: (SELECT ...) triggers an initPlan - Postgres evaluates it once
-- and reuses the value for every row in the query
USING ((SELECT public.current_user_id()) = user_id)
```

<cite index="11-1">This approach wrapping functions in SELECT statements can improve
query performance by 57-61% for common query types.</cite> It is only valid for
functions whose result does not change based on row data (i.e., they don't
take row columns as input).

**Do not enable RLS on reference or lookup tables.** Country lists,
currencies, notification types, and similar tables have no user-specific
rows. Enabling RLS on them adds overhead for zero security gain. RLS is
for tables where row ownership matters.

**Do not use correlated subqueries in RLS policies.** <cite index="13-1">Passing row data
to a function in a policy means every row that passes the WHERE filter
requires a separate function call. Functions in Postgres are slow; calling
one N times per row makes performance scale exponentially.</cite> Use
`SECURITY DEFINER` functions that query needed data without taking row
parameters instead.

**Run `EXPLAIN ANALYZE` from the app role, not as superuser.** RLS policies
don't apply to superusers. Testing query plans as the table owner means you
never see the actual plan the app executes.

```sql
-- Test as the actual application role to see real query plans
SET ROLE app_role;
SET LOCAL app.current_user_id = 'some-uuid-here';
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM documents WHERE status = 'pending';
RESET ROLE;
```

### P3. Rate limiting: match the store to the consistency requirement

DB-backed rate limiting (logging attempts to a table, querying counts) adds
a full round-trip to your origin database on every login attempt. That is
acceptable for low-traffic applications, but there are faster options.

<cite index="23-1">**Do not use Workers KV for rate limiting.** KV is eventually
consistent. Two concurrent requests can both read the same stale count,
both decide they are under the limit, and both proceed - which is exactly
what rate limiting is supposed to prevent.</cite>

**On Cloudflare Workers, use Durable Objects for rate limiting.** <cite index="21-1">Durable
Objects provide strong consistency (strict serializability) and can handle
approximately 500-1,000 requests per second per object for simple
operations.</cite> Create one Durable Object per IP or per user identifier
(not one global object for all traffic):

```javascript
// One DO per IP - strongly consistent, no race condition
const id = env.RATE_LIMITER.idFromName(`login:${clientIp}`);
const stub = env.RATE_LIMITER.get(id);
const allowed = await stub.fetch('/check');
```

**For non-edge deployments, Redis/Upstash** with atomic `INCR` + `EXPIRE`
is the standard approach. It is a single round-trip with no race condition.

**DB-backed rate limiting is fine for low-traffic or simple stacks** where
the origin DB round-trip budget is acceptable and you are not running at
Cloudflare edge. Make the count-check-and-insert atomic with a single
upsert or advisory lock (see section L in `SKILL.md`).

**Use Cloudflare's built-in Rate Limiting rules** for broad IP-based
limiting before requests even hit your Worker. This is free, zero-latency,
and requires no code.

### P4. JWT: verify once, cache in the request context

`crypto.subtle.verify()` is fast (microseconds), but calling it multiple
times per request for the same token is unnecessary work. Verify once at
the request entry point, attach the decoded claims to the request context
object, and pass that to all downstream handlers:

```javascript
// In the top-level auth guard (ONCE per request):
export async function onRequest(context) {
  if (!PUBLIC_ROUTES.has(path)) {
    const claims = await verifyAndDecodJWT(context.request); // ONE verify call
    if (!claims) return new Response('Unauthorized', { status: 401 });
    context.user = claims; // attach to context, no re-verify needed downstream
  }
}

// In a handler: just read context.user, never re-verify
async function handleProfile(context) {
  const userId = context.user.sub; // already verified
}
```

**HMAC-SHA256 (`crypto.subtle`) is faster than RSA-SHA256** for
verification. For APIs where you control both the signing and verification
side (no third parties verifying tokens), HMAC is a valid, faster choice.
RSA is required only when third parties need to verify tokens without sharing
a secret.

**KV for session data is appropriate.** <cite index="20-1">Cloudflare recommends Workers
KV for session tokens: hot keys see latency of 500µs-10ms, writes happen
only on login/logout, and eventual consistency rarely matters since users
typically interact with one edge location.</cite> Use short-lived JWTs (≤ 1 hour)
so stale KV session state has a bounded validity window.

### P5. Connection pooling: required for serverless + Postgres

Every serverless invocation would open a new TCP+TLS connection to Postgres
without a connection pooler. At scale that exceeds Postgres's connection
limit and degrades performance for everyone. A connection pooler is not
optional at serverless scale - it is a correctness requirement.

**Supabase:** Use Supavisor (the built-in pooler) in **transaction mode**
for serverless/edge. Transaction mode means each query gets a fresh
connection from the pool, and the connection is returned immediately after
the transaction ends. This is why `SET LOCAL` (transaction-scoped) is the
security-correct choice for RLS session variables - it automatically clears
when the connection goes back to the pool, preventing context leakage to the
next user. Session mode (`SET` without `LOCAL`) is incompatible with
transaction-mode pooling for this reason.

**Cloudflare:** Use Hyperdrive between Workers and your Postgres database.
Hyperdrive keeps a connection pool warm close to the physical database,
eliminating the TCP+TLS setup cost per Worker invocation. It also caches
read queries at the edge when configured to do so.

### P6. Pre-signed URL caching

Generating a new pre-signed URL on every request that serves the same
document wastes CPU time and adds latency. Cache pre-signed URLs for most
of their validity window:

```javascript
// First request for a document in the current session: generate + cache
// Subsequent requests: return the cached URL if still valid

const CACHE_MARGIN_SECONDS = 60; // regenerate 60s before expiry
const URL_TTL_SECONDS = 900;     // 15 minutes

async function getDocumentUrl(docId, userId) {
  const cacheKey = `presigned:${userId}:${docId}`;
  const cached = await env.KV.get(cacheKey, { type: 'json' });
  if (cached && cached.expiresAt > Date.now() / 1000 + CACHE_MARGIN_SECONDS) {
    return cached.url;
  }
  // Verify ownership before signing (IDOR check)
  const doc = await db.getDoc(docId, userId);
  if (!doc) throw new NotFoundError();
  const url = await getSignedUrl(env.R2, doc.object_key, { expiresIn: URL_TTL_SECONDS });
  await env.KV.put(cacheKey, JSON.stringify({
    url, expiresAt: Math.floor(Date.now() / 1000) + URL_TTL_SECONDS
  }), { expirationTtl: URL_TTL_SECONDS - CACHE_MARGIN_SECONDS });
  return url;
}
```

Note: KV's eventual consistency is acceptable here - a slightly stale cached
URL still works until its actual expiry. The ownership check happens on cache
miss (generation), not on cache hit, which is the correct security model.

### P7. The golden rule: measure before you change anything

Security controls that genuinely affect performance can only be optimized
after you know **which controls** are slow and **by how much**, in production,
under real load. Do not remove security controls because they seem slow.
Instrument first.

- **Postgres:** `EXPLAIN (ANALYZE, BUFFERS)` from the application role.
  Look for sequential scans on large tables, per-row function calls in
  filter steps, and plan cache invalidations.
- **Edge functions:** Use `Date.now()` timing spans around each major
  operation (JWT verify, DB query, R2 sign, RLS binding RPC) and log them.
  Identify the actual bottleneck before changing anything.
- **Load test authentication:** A login endpoint that works fine at 1 req/s
  may collapse at 50 req/s due to bcrypt CPU saturation. Load-test auth
  endpoints specifically at the expected concurrent-user count, not just
  average throughput.

---

## Q. Login and signup flow edge cases

Every authentication flow has a set of edge cases that are either silently
ignored or handled insecurely in most codebases. This section defines the
correct behavior for each one. Get these wrong and you either leak account
information to attackers or create a broken experience for real users.

The core rule that governs everything below: **unauthenticated requests must
never reveal whether a specific email address has an account.** An attacker
who can distinguish "email exists" from "email not found" can enumerate your
entire user base one address at a time.

### Q1. Signup with an email that already has an account

**What most apps do:** Return an error like "Email already registered."
**Why this is wrong:** It confirms to an attacker that the email is in the
database. If they are targeting a specific person, they now know that person
is a user of your service.

**Correct behavior:**
- Return the same success-looking response as a normal signup: "Check your
  inbox to verify your email."
- In the background, send a different email to the address on file: "Someone
  tried to register a new account with your email address. If this was you
  and you forgot your password, use the link below to reset it. If this was
  not you, no action is needed."
- This gives the real account owner a security notification while revealing
  nothing to the person who submitted the form.

**Special sub-cases:**
- **Email exists but account is unverified:** Resend the verification email
  instead of creating a duplicate. Same outward response.
- **Email exists but account was deleted:** Treat as a fresh signup. Deleted
  accounts should not block re-registration. If you soft-delete, check
  whether the email is in the active OR the deleted set before deciding.
- **Email exists via OAuth/SSO with no password set:** Send an email
  explaining the account uses social login, with a link to add a password if
  desired. Do not create a duplicate password-based account for the same
  email.
- **Email exists but is pending minor/guardian consent:** Do not reveal this
  state. Treat it as a normal "check your inbox" response. The in-progress
  consent flow gets a separate notification.

### Q2. Login failures: wrong password vs email not found

**Both must return exactly the same message and take the same time.**

```
"Incorrect email or password."
```

Never:
- "No account found with that email."
- "Wrong password."
- "Account not found." vs "Invalid credentials." (even subtle wording
  differences are enumerable at scale)

**Timing:** bcrypt/Argon2id adds natural latency to a successful password
check. When the email does not exist, there is no hash to compare against, so
the response returns faster. An attacker measuring response times can
distinguish the two even with identical messages.

Fix: always run the hash comparison even when the email is not found, against
a dummy hash stored at startup:

```javascript
// At startup - load once, reuse for all "not found" comparisons
const DUMMY_HASH = await bcrypt.hash('dummy-value-never-used', 12);

async function login(email, password) {
  const user = await db.getUserByEmail(email);

  if (!user) {
    // Always compare to prevent timing-based enumeration
    await bcrypt.compare(password, DUMMY_HASH);
    return invalidCredentials();
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return invalidCredentials();

  return issueSession(user);
}
```

### Q3. Login with a valid email and password, but account has a special state

These are the cases where a user's credentials are technically correct but
the login should still be blocked. Each requires a different response
strategy depending on whether revealing the state leaks information.

| Account state | What to tell the user | Security note |
|---|---|---|
| Email not verified | "Please verify your email before logging in. Resend link?" | Reveals account exists - acceptable tradeoff for UX; document this decision |
| Account locked (too many attempts) | "Your account is temporarily locked. Try again in X minutes or reset your password." | Lock on the account identifier, not the IP |
| Account disabled by admin | "This account has been suspended. Contact support." | Do not specify why unless the user is authenticated in a support channel |
| Account pending approval | "Your account is under review. You will receive an email when it is approved." | Only reveal this if your signup flow explicitly promises a review step |
| MFA required, not yet provided | Redirect to MFA step. Do not complete login. | Session at this point must be a partial "pre-MFA" session with no data access |
| MFA code wrong | "Incorrect code. X attempts remaining." | Rate-limit and lock MFA separately from the password step |

**Account lockout specifics:**
- Lock on the email/username, not the IP. An attacker using a proxy pool
  bypasses IP-based lockout trivially.
- Lock on BOTH, independently. An attacker targeting one account from many
  IPs is stopped by email-based lockout. Many accounts from one IP is stopped
  by IP-based lockout.
- Unlock via time (preferred) or via password-reset email (also acceptable).
  Do not unlock automatically on a correct password without resetting the
  counter - this allows slow-rate attacks.
- Log every lockout event with IP, user agent, and timestamp for audit.

### Q4. Password reset edge cases

**Reset request for a non-existent email:**
Always respond: "If an account exists with that email, a reset link has been
sent." Never distinguish between "sent" and "not sent."

**Multiple reset requests for the same email:**
Each new reset request must invalidate all previous unredeemed tokens for
that user. A user who requests three resets should only be able to use the
link from the third email. Store the token hash in the database and check
`used = false` - when issuing a new token, set all previous tokens for
that `user_id` to `used = true`.

```sql
-- Invalidate all previous tokens before inserting the new one
UPDATE password_reset_tokens
SET used = true
WHERE user_id = $1 AND used = false;

INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, now() + interval '1 hour');
```

**Reset token reuse:**
Mark the token as used the moment it is verified, before the password is
changed. If the password change fails after marking the token used, issue a
new token rather than re-enabling the old one. This prevents a race condition
where two concurrent redemptions of the same token both succeed.

**Reset for a locked account:**
Allow it. Password reset is the intended unlock mechanism. After a
successful reset, clear the failed-attempt counter and unlock the account.

**Reset for an unverified account:**
Allow it, but also mark the email as verified on success. A user who can
receive email at that address has effectively verified it.

**Reset token expiry:**
Tokens must expire. One hour is the standard. After expiry, the link in the
email must show a clear "This link has expired" message with a direct link to
request a new one - not a generic 404 or 500.

### Q5. Re-registration after account deletion

If your app supports account deletion, define clearly whether deletion is
hard (permanent) or soft (flag in DB, data retained). The behavior differs:

- **Hard delete:** The email is fully released. A new signup with that email
  creates a fresh account with no history. Treat exactly like a first-time
  signup.
- **Soft delete:** The email is technically still in the database.
  - Do not tell the person signing up that a deleted account exists for that
    email (this leaks that someone previously used the service).
  - Either release the email at deletion time (set it to a hashed/anonymous
    value) so it is freely re-registrable, or re-activate the old record if
    you need to preserve history.
  - If you re-activate: send a "Welcome back" email and explain the account
    was restored, so the user is not confused by seeing old data.

### Q6. Concurrent and cross-device session handling

Decide on a session policy and enforce it consistently:

- **Unlimited sessions (default for most apps):** Every login issues a new
  session. Old sessions remain valid until they expire or the user explicitly
  logs out. Simple but means a compromised device stays active until expiry.
- **Single active session:** Each new login invalidates all previous sessions.
  Store a session version counter on the user record; increment it on every
  login; embed it in the JWT. On each request, verify the counter in the
  token matches the one in the database. Slower (requires a DB read per
  request) but gives the user effective "log out everywhere" control.
- **Capped sessions (e.g., max 5 devices):** Track active sessions in a table.
  On login, if the cap is reached, invalidate the oldest session. Show the
  user their active sessions in account settings so they can audit them.

Regardless of which policy you choose:
- Always invalidate all sessions on password change.
- Always invalidate all sessions on email change.
- Provide a "log out all other devices" button in account settings.

### Q7. The complete response decision matrix

```
Unauthenticated request           Reveal?   Message
------------------------------------------------------------------
"Is this email registered?"        NO        Never expose this endpoint
Signup: email already exists       NO        "Check your inbox"
Signup: email already unverified   NO        "Check your inbox" (resend)
Signup: email from deleted acct    NO        "Check your inbox"
Login: email not found             NO        "Incorrect email or password"
Login: email found, wrong pass     NO        "Incorrect email or password"
Login: account locked              YES*      "Account temporarily locked"
Login: account unverified          YES*      "Please verify your email"
Login: account disabled            YES       "Account suspended"
Password reset: email not found    NO        "If account exists, email sent"
Password reset: token expired      YES       "Link expired - request a new one"
Password reset: token used         YES       "Link already used - request a new one"

*Revealing these states leaks account existence. Accepted UX tradeoff -
 document the decision. Some high-security apps keep all failures identical.
```

---

## R. RLS drift: existing policies bypassed by new query paths

RLS being enabled on a table is not enough if a new code path writes to
that table without going through the session-binding RPC that sets the user
context. This is called RLS drift: the policy exists and is correct, but a
new mutation quietly bypasses it.

It happens constantly with AI-assisted development. The agent writes a new
API route, uses the Supabase client directly, and the UPDATE or DELETE runs
with the service role or an unauthenticated client that skips row filtering
entirely.

**Check every new mutation (INSERT, UPDATE, DELETE) against this list:**

- Does the route go through the session-binding RPC before touching the table?
  If the app uses a pattern like `set_current_user(uid)` before queries, every
  new route must call it.
- Does the query include an explicit `user_id = current_user.id` WHERE clause,
  or does it rely purely on RLS? If it relies on RLS, confirm the session
  context is set before the query runs - not just before the SELECT.
- Is the Supabase client used in the route the anon/user client (respects RLS)
  or the service role client (bypasses RLS entirely)? A mutation using the
  service role client has no RLS protection regardless of the policy.
- Does the API route validate ownership before mutating? An RLS policy on
  SELECT does not automatically protect UPDATE. Check that an UPDATE policy
  with a WITH CHECK clause also exists.

**The drift pattern to watch for:**

```typescript
// DRIFTED - new route added, service role client used, RLS bypassed silently
export async function POST(req: Request) {
  const { id, status } = await req.json();
  const user = await getUser(req); // auth check present
  // but supabaseAdmin bypasses all RLS - any user can update any row
  await supabaseAdmin.from('applications').update({ status }).eq('id', id);
}

// CORRECT - uses user-scoped client after binding session
export async function POST(req: Request) {
  const user = await getUser(req);
  const supabase = createClient({ userId: user.id }); // RLS context set
  await supabase.from('applications')
    .update({ status })
    .eq('id', id)
    .eq('user_id', user.id); // explicit ownership filter as backstop
}
```

**Schema drift:** When a new table is added via migration but no RLS policy
is written for it, all existing app code that references it runs without row
security. Every migration file that contains a CREATE TABLE must also contain
ENABLE ROW LEVEL SECURITY and at least one policy for that table in the same
file or a paired migration. Never leave RLS as a follow-up task.

---

## S. Unsafe execution paths: command execution from SQL and application code

PostgreSQL has several features that execute OS commands or read the file
system. These are legitimate for DBAs but are serious vulnerabilities if
reachable from application code or untrusted input.

### S1. COPY TO/FROM PROGRAM

`COPY (SELECT ...) TO PROGRAM 'cmd'` executes an arbitrary OS command as
the PostgreSQL OS user. `COPY ... FROM PROGRAM 'cmd'` reads stdout from a
command into a table. If any part of the command string comes from user input
or a database column, this is a command injection vulnerability with full OS
access.

```sql
-- DANGEROUS: command string built from user-controlled data
COPY (SELECT data FROM uploads WHERE id = $1)
  TO PROGRAM 'gzip > /tmp/' || user_supplied_filename;

-- Also dangerous in a PL/pgSQL function
EXECUTE 'COPY ... TO PROGRAM ''' || cmd_string || '''';
```

Block access entirely: revoke the `pg_execute_server_program` role from the
application role. Application code should never need COPY TO PROGRAM.

### S2. pg_read_file, pg_write_file, pg_ls_dir

These superuser functions read and write arbitrary files on the PostgreSQL
server's file system. They are intended for DBA diagnostics. If they are
callable from an application role or from a SECURITY DEFINER function that
an application role can invoke, they are a read/write primitive on the
server OS.

```sql
-- Readable from application code? This is a full server file system reader
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file(user_supplied_path); -- directory traversal
```

Mitigation: never grant `pg_monitor` or `pg_read_server_files` to the
application role. Audit SECURITY DEFINER functions for calls to these.

### S3. lo_import, lo_export (large object file I/O)

`lo_import('/path/to/file')` reads a file from the server's file system into
a large object. `lo_export(oid, '/path/to/file')` writes a large object to
the server's file system. These require superuser privileges but are
sometimes granted to application roles via SECURITY DEFINER wrappers.

```sql
-- Writing attacker-controlled content to server file system
SELECT lo_export(lo_from_bytea(0, decode($1, 'hex')), '/var/spool/cron/postgres');
```

The pgAdmin 4 CVE-2026-12044 exploit chain used exactly this pattern: an
AI assistant prompt injection led to `COPY TO PROGRAM` execution through a
SECURITY DEFINER wrapper. Audit every SECURITY DEFINER function that touches
lo_import, lo_export, or COPY.

### S4. exec/spawn/execSync in server-side application code

When server-side code calls `child_process.exec()`, `spawn()`, or
`execSync()` with any value derived from a database query, user input, or
a file path - this is OS command injection at the application layer.

```javascript
// DANGEROUS: filename from DB used in shell command
const { filename } = await db.query('SELECT filename FROM uploads WHERE id=$1', [id]);
exec(`convert ${filename} output.png`); // shell injection if filename = "; rm -rf /"

// SAFE: use execFile with an argument array, never exec with a template string
execFile('convert', [filename, 'output.png']); // no shell interpretation
```

Rule: never use `exec()` or `execSync()` in server code. Use `execFile()` or
`spawn()` with an explicit argument array. Never build a shell command string
from any external value.
