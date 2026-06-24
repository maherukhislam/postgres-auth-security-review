# postgres-auth-security-review

> An [Agent Skill](https://agentskills.io) that reviews and writes
> PostgreSQL/Supabase authentication code against a researched set of
> known vulnerabilities - before it ships.

[![Agent Skills](https://img.shields.io/badge/agent--skills-1.3.0-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Validate skill](https://github.com/maherukhislam/postgres-auth-security-review/actions/workflows/validate.yml/badge.svg)](https://github.com/maherukhislam/postgres-auth-security-review/actions/workflows/validate.yml)

Works in **Codex CLI**, **Antigravity**, **Claude Code**, **Cursor**,
**Gemini CLI**, and **GitHub Copilot** - any agent that supports the open
[agentskills.io](https://agentskills.io) standard.

---

## What it does

The skill activates automatically when a task touches login, signup,
password-reset, JWT/session handling, SQL queries, migrations, Row-Level
Security (RLS) policies, Postgres roles/grants, Supabase client-key usage,
custom JWT implementations (crypto.subtle / HMAC), serverless/edge function
routing, object storage (R2/S3/GCS), DB-backed rate limiting, or
minor/guardian consent flows. It applies a set of non-negotiable rules and
flags anything that would ship with a known security hole - inline fix where
it can, explicit warning where it can't.

**Covers:**

| Area | What it checks |
|---|---|
| Row-Level Security | `ENABLE RLS`, `FORCE ROW LEVEL SECURITY`, `USING(true)` trap, partial-op coverage, table-owner bypass, materialized view bypass |
| Custom RLS session binding | Fail-open RPC errors, `is_admin()` fail-open, `SET` vs `SET LOCAL` pool leak, session-binding error handling |
| Postgres roles | Least-privilege app role, `PUBLIC` schema `CREATE`, `SECURITY DEFINER` + `search_path` |
| SQL injection | Parameterized queries everywhere, including inside `PL/pgSQL EXECUTE`, libpq escape function misuse |
| Password hashing | Argon2id (preferred) or bcrypt cost ≥ 12; never `md5()`/`crypt()` in SQL; runtime-aware advice |
| Custom JWT (crypto.subtle) | Algorithm pinning, `alg:none` rejection, claim verification order, HMAC secret entropy, constant-time comparison |
| Standard JWT libraries | Algorithm allowlist, `alg:none`, token storage in httpOnly cookies |
| Serverless / edge routing | Catch-all auth guards, module-scope variable leakage, path normalization |
| Object storage (R2/S3/GCS) | Private buckets, random UUID keys (IDOR prevention), pre-signed URL expiry, CORS, ownership check |
| DB-backed rate limiting | IP spoofing via `X-Forwarded-For`, count-then-insert race condition, per-account limiting |
| Minor / guardian consent | Server-side age verification, immutable consent records, IP source in consent logs |
| Secret management | No `service_role` keys in client bundles or `NEXT_PUBLIC_` vars; no secrets in git history |
| Multi-tenancy | RLS-enforced isolation, not just app-layer `WHERE tenant_id = ?` |
| Supply chain | Postgres version against known CVEs, pgjdbc version, unpinned deps |
| Engineering trade-offs | Performance vs security guidance: bcrypt on edge runtimes, RLS indexing, rate-limit store selection, JWT caching, connection pooling |

Built on named CVEs (not vibes): OWASP Top 10:2025, NIST SP 800-63B,
CVE-2025-1094, CVE-2025-29927, CVE-2025-48757, CVE-2024-10976,
CVE-2026-2004, CVE-2026-2005, and more. See
[`skills/postgres-auth-security-review/references/checklist.md`](skills/postgres-auth-security-review/references/checklist.md)
for full reasoning and sources.

---

## Install

### GitHub CLI (recommended)

```bash
# Install into the current project (project scope)
gh skill install maherukhislam/postgres-auth-security-review

# Install globally for all your projects (user scope)
gh skill install maherukhislam/postgres-auth-security-review --scope user

# Target a specific agent
gh skill install maherukhislam/postgres-auth-security-review --agent codex
gh skill install maherukhislam/postgres-auth-security-review --agent claude-code
```

### Manual (copy-paste)

```bash
git clone https://github.com/maherukhislam/postgres-auth-security-review.git
cp -r postgres-auth-security-review/skills/postgres-auth-security-review \
      .agents/skills/
```

<details>
<summary>Where each agent looks for skills</summary>

| Agent | Project scope | User scope |
|---|---|---|
| Codex CLI | `.agents/skills/` | `~/.codex/skills/` |
| Antigravity | `.agents/skills/` | `~/.gemini/antigravity/skills/` |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` |
| Cursor | `.agents/skills/` | `~/.cursor/skills/` |
| Gemini CLI | `.agents/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `.agents/skills/` | `~/.copilot/skills/` |

At project scope, Codex, Antigravity, Cursor, Gemini CLI, and Copilot all
share `.agents/skills/`. Claude Code uses `.claude/skills/` instead.

</details>

---

## Run the scanner manually

The scan script is plain `grep` - no network calls, no code execution, safe
to run any time:

```bash
bash .agents/skills/postgres-auth-security-review/scripts/scan_auth_security.sh /path/to/repo
```

It exits non-zero if it finds anything, so you can also wire it into CI:

```yaml
# .github/workflows/security-scan.yml
- name: Auth security scan
  run: |
    bash .agents/skills/postgres-auth-security-review/scripts/scan_auth_security.sh .
```

The scanner covers 17 pattern groups across: outdated Postgres versions,
permissive RLS policies, service-role key exposure, `sslmode=disable`,
weak password hashing, custom JWT pitfalls, catch-all routing without auth
guards, pre-signed URLs without expiry, object key IDOR, `X-Forwarded-For`
IP spoofing, `SECURITY DEFINER` without locked `search_path`, RLS
session-binding errors, rate-limit race conditions, cookie flags, minor
consent client-side-only checks, password-reset single-use enforcement,
and supply chain version pinning.

---

## File map

```
skills/
└── postgres-auth-security-review/
    ├── SKILL.md                   # Core rules the agent reads when triggered
    ├── references/
    │   └── checklist.md           # Full reasoning, CVE case studies, exact parameters
    └── scripts/
        └── scan_auth_security.sh  # Read-only grep scanner, 17+ pattern groups
```

---

## Updating

```bash
gh skill update maherukhislam/postgres-auth-security-review
```

Or `git pull` + re-copy if you installed manually.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs run the validation CI
automatically. New patterns need a source (CVE, OWASP, NIST, or a documented
incident) - no speculation.

## License

MIT - see [LICENSE](LICENSE).
