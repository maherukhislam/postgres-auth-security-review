# Changelog

All notable changes to this skill are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [1.1.0] — 2026-06-19

### Added — new CVE coverage
- **CVE-2025-1094 (CVSS 8.1)** — psql SQL injection via invalid UTF-8 in
  `PQescapeLiteral()`/`PQescapeIdentifier()`. Exploited in the US Treasury
  BeyondTrust breach chain. Scan pattern added for libpq escape function use.
- **CVE-2025-8714 / CVE-2025-8715** — `pg_dump` object-name injection. Both
  client-side OS command execution and SQL injection at restore time.
- **CVE-2026-2004 (CVSS 8.8)** — PostgreSQL `intarray` extension arbitrary
  code execution via crafted selectivity estimator input.
- **CVE-2026-2005 (CVSS 8.8)** — PostgreSQL `pgcrypto` heap buffer overflow,
  code execution as the OS user running the database.
- **pgjdbc channel-binding bypass (2025-06-11, CVSS 8.2)** — JDBC driver
  silently downgrades from required channel binding to weaker auth methods,
  enabling MITM interception.
- **CVE-2024-10976** — Query plan caching discards correct RLS policy when
  plan is created under one role and executed under another. Affects `SET ROLE`,
  `SECURITY DEFINER` functions, subqueries, `WITH` queries, and
  security-invoker views.
- **CVE-2025-29927 (CVSS 9.1)** — Next.js middleware auth bypass via
  `x-middleware-subrequest` header. Affects self-hosted Next.js < 12.3.5,
  < 13.5.9, < 14.2.25, < 15.2.3. Added scan pattern and architectural rule.
- **CVE-2025-48757** — Supabase/Lovable apps with RLS disabled exposed via
  public anon key. Detailed case study in references/checklist.md.
- Supabase 2025/2026 key model changes (asymmetric publishable/secret keys,
  GitHub Secret Scanning auto-revocation, RLS on by default for dashboard
  tables).

### Added — new scan checks (scripts/scan_auth_security.sh)
- Outdated Postgres Docker image (below safe minimums for mid-2026)
- `WITH CHECK (true)` permissive write policy
- bcrypt cost factor below 12
- `alg: none` in JWT configuration
- JWT token stored in `localStorage`/`sessionStorage`
- `PQescapeLiteral`/`PQescapeIdentifier` usage (CVE-2025-1094 class)
- `EXECUTE … ||` concatenation inside PL/pgSQL
- `x-middleware-subrequest` in Next.js middleware files
- Next.js middleware detection (advisory to also validate in API routes)
- Cookie without `httpOnly` flag
- `SameSite=None` without `Secure`
- Unpinned Postgres/pgjdbc in dependency files

### Added — new SKILL.md sections
- Section A: PostgreSQL version and patch status (with version table)
- Session fixation rule
- OAuth 2.0 requirements (PKCE, state parameter)
- Extended final-scan gate from 7 to 10 items

### Changed
- `metadata.version` bumped to `1.1.0`
- Checklist expanded from 15 to 22 items
- References expanded with all new CVE sources

---

## [1.0.0] — 2026-06-19

### Added
- `SKILL.md` with core Postgres/Supabase and auth security rules
- `references/checklist.md` with Argon2id/bcrypt parameters, CVE-2025-48757
  case study, SECURITY DEFINER `search_path` chain, JWT algorithm confusion,
  OWASP Top 10:2025 context
- `scripts/scan_auth_security.sh` — 7-pattern static scanner
- `.github/workflows/validate.yml` — CI validation of SKILL.md frontmatter

## [1.2.0] — 2026-06-21

### Context
This release was informed by auditing a real Jamstack production stack:
React 19 SPA on Cloudflare Pages, serverless edge functions as a catch-all
API gateway, Supabase PostgreSQL with custom RLS session-binding via PL/pgSQL,
bcryptjs (cost 12), custom JWT via crypto.subtle/HMAC-SHA256, Cloudflare R2
for sensitive document storage, DB-backed rate limiting, and minor/guardian
consent flows. The new rules are written generically so they apply to any
stack with these architectural patterns.

### Added — new SKILL.md sections
- **Section C: Custom RLS session-binding functions** — fail-open on RPC error,
  `is_admin()` failing open, SET vs SET LOCAL leak in connection pools,
  materialized views bypassing RLS.
- **Section G: Custom JWT via crypto.subtle / HMAC** — algorithm pinning,
  alg:none rejection, claim verification order (signature before payload read),
  token lifetime (7-day tokens are risky), HMAC secret entropy, constant-time
  comparison requirement.
- **Section H: Serverless / edge function routing security** — catch-all
  routing without top-level auth guard, module-scope variable leakage between
  warm requests, path normalization, error response leakage.
- **Section I: Object storage (R2 / S3 / GCS)** — private bucket requirement,
  random object keys vs user-ID-based keys (IDOR), pre-signed URL expiry,
  server-side MIME/size validation, CORS lockdown, ownership check before
  signed URL issuance, delete-alongside-DB-row.
- **Section L: DB-backed rate limiting** — IP spoofing via X-Forwarded-For,
  race condition on count-then-insert, per-account limiting, async pruning
  gap, password logging risk.
- **Section M: Minor / guardian consent flows** — server-side age verification,
  immutable consent records, IP spoofing in consent logs, guardian notification,
  date-of-birth update re-verification.
- Final scan gate expanded from 10 to 20 items.

### Added — new scan patterns (scripts/scan_auth_security.sh)
- `B4` — `CREATE MATERIALIZED VIEW` advisory (RLS does not apply at query time)
- `F1` — `crypto.subtle` usage without visible `alg:none` rejection
- `F2` — JWT payload parsed before `crypto.subtle.verify()` (authentication bypass)
- `F3` — Token compared with `===` (timing attack surface)
- `F4` — JWT expiry > 24 hours
- `H1` — Catch-all route file advisory (top-level auth guard check)
- `H2` — Module-scope mutable variable in edge function (warm-instance leak)
- `I1` — Pre-signed URL without expiry parameter
- `I2` — Object key constructed from user ID (IDOR at storage layer)
- `I3` — Public bucket access policy
- `L1` — `set_config` with `is_local=false` (session-scoped, pool leak)
- `L2` — Exception handler returning `true` in auth function (fail-open)
- `L3` — RLS session-binding RPC without error handling
- `M1/M2` — `X-Forwarded-For` as rate-limit IP source
- `O1` — Age/minor check in client component only
- `O2` — `legal_consents` table without immutability policy advisory
- `P1` — Reset token compared with `===`
- `P2` — Reset token query without `used=false` check
- Scanner version bumped to `v1.2.0`; `.wrangler` added to exclude dirs

### Added — references/checklist.md
- Section 3: Custom RLS session binding — full code examples for all four
  failure modes (fail-open policy, is_admin() fail-open, SET vs SET LOCAL,
  RPC error not caught)
- Section 6: Custom JWT with crypto.subtle — algorithm pinning, alg:none,
  claim verification order, lifetime, secret requirements, constant-time
  comparison (all with code examples)
- Section 7: Serverless edge routing — catch-all guard pattern, module-scope
  leak, path normalization (all with code examples)
- Section 8: Object storage — key design, pre-signed URL expiry, CORS,
  server-side file validation (all with code examples)
- Section 9: DB-backed rate limiting — IP source, atomic count-insert,
  per-account limiting (code examples)
- Section 10: Password-reset token security — full schema + issue/redeem code
- Section 11: Minor/guardian consent — SQL schema + server-side age calculation
- Full checklist expanded from 22 to 30 items
- Sources expanded: Web Crypto API spec, Cloudflare Workers runtime docs

### Changed
- `metadata.version` bumped to `1.2.0`
- Description updated to include new trigger categories

## [1.3.0] — 2026-06-23

### Added — Section P: Engineering Trade-offs (security without killing performance)

The core insight: security slowdowns are almost always symptoms of a wrong
implementation, not an inherent cost of the control. This section gives
concrete, research-backed guidance on building the right implementation.

**P1 — Password hashing: match the algorithm to the runtime**
Pure JavaScript Argon2id consumes ~14,000ms CPU time per hash in a V8
isolate; pure JS bcrypt ~2,000ms. On Cloudflare Workers the solution is a
Rust-based Worker via Cloudflare Service Binding (~100ms). The rule: move
hashing out of the main edge function rather than weakening the cost factor.
Target ≥ 200ms per hash on production hardware (calibrate to your instance
type — the same cost factor varies between 60ms and 250ms across CPU models).
Always use the async bcrypt/argon2 API. Bound the hashing worker pool to
prevent login-spike DoS from hash CPU saturation.

**P2 — RLS: the performance issue is almost always a missing index**
RLS itself adds ~1.6ms overhead at 100K rows (< 2%). The 26× performance
cliff people hit is a sequential scan from missing indexes on RLS predicate
columns. Adding the right B-tree index drops a count query from ~73ms to
~2.2ms. Wrapping session-context functions in `(SELECT func())` triggers
Postgres's initPlan and caches the result once per transaction instead of
per-row — achieving 57–61% improvement on common query types. Do not enable
RLS on reference/lookup tables. Do not use correlated subqueries in policies.
Always run EXPLAIN ANALYZE from the application role, not superuser.

**P3 — Rate limiting: match the store to the consistency requirement**
Workers KV is eventually consistent and actively wrong for rate limiting:
two concurrent requests can both read a stale count and both proceed. The
correct choice on Cloudflare Workers is Durable Objects (strictly
consistent, 500–1,000 req/s per object). On other stacks: Redis/Upstash
atomic INCR+EXPIRE. DB-backed rate limiting is fine for low-traffic apps.
Use Cloudflare's built-in Rate Limiting rules as a zero-latency first layer.

**P4 — JWT: verify once, cache in request context**
Verify the JWT once at the top-level auth guard, attach decoded claims to
the request context object, and read `context.user` in all handlers — no
re-verification. HMAC-SHA256 (crypto.subtle) is faster than RSA-SHA256 for
symmetric setups. Workers KV is appropriate for session token storage: hot
keys at 500µs–10ms, eventual consistency acceptable since users interact
with one edge location.

**P5 — Connection pooling: required for serverless + Postgres**
Without a pooler, every serverless invocation opens a new TCP+TLS connection,
exhausting Postgres's connection limit at scale. Use Supavisor (Supabase) in
transaction mode or Hyperdrive (Cloudflare). Transaction-mode pooling is also
why SET LOCAL (is_local=true) is the security-correct choice for RLS session
variables — session-scoped SET leaks user context to the next pooled request.

**P6 — Pre-signed URL caching**
Generate pre-signed URLs once and cache them in KV for most of their
validity window. Regenerate only when the cached URL is within 60 seconds
of expiry. The ownership IDOR check runs only at cache-miss (generation)
time, not on every cache hit. KV eventual consistency is acceptable here —
a slightly stale URL still works until actual expiry.

**P7 — Measure before changing anything**
Instrument with `EXPLAIN (ANALYZE, BUFFERS)` from the app role for Postgres;
`Date.now()` spans for edge function operations; dedicated load testing of
auth endpoints at expected concurrent-user count. Never remove a security
control because it seems slow — find the actual bottleneck first.

### Sources added (P section)
- Cloudflare Workers CPU limits — developers.cloudflare.com/changelog/2025-03-25
- Lucia Auth / Rust Argon2 on Cloudflare Workers — mli.puffinsystems.com
- MojoAuth: CPU Bottlenecks in Password Hashing Under High Traffic
- "Does Postgres RLS actually ruin performance?" benchmark — dev.to
- Supabase RLS Performance Discussion (Gary Austin) — github.com/orgs/supabase
- Optimizing RLS Performance with Supabase — antstack.com
- Scott Pierce: Optimizing Postgres RLS — scottpierce.dev
- Architecting on Cloudflare (Ch. 11, 14): Storage trade-offs — architectingoncloudflare.com
- Cloudflare Durable Objects docs: rules, limits, what they are
- Cloudflare Workers storage options docs — developers.cloudflare.com
