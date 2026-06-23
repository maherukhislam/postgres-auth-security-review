# postgres-auth-security-review

> An [Agent Skill](https://agentskills.io) that reviews and writes
> PostgreSQL/Supabase authentication code against a researched set of
> common and uncommon security mistakes - before it ships.

[![Agent Skills](https://img.shields.io/badge/agent--skills-1.0.0-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Validate skill](https://github.com/maherukhislam/postgres-auth-security-review/actions/workflows/validate.yml/badge.svg)](https://github.com/maherukhislam/postgres-auth-security-review/actions/workflows/validate.yml)

Works in **Codex CLI**, **Antigravity**, **Claude Code**, **Cursor**,
**Gemini CLI**, and **GitHub Copilot** - any agent that supports the open
[agentskills.io](https://agentskills.io) standard.

---

## What it does

The skill activates automatically when a task touches login, signup,
password-reset, JWT/session handling, SQL queries, migrations, Row-Level
Security (RLS) policies, Postgres roles/grants, or Supabase client-key usage.
It then applies a set of non-negotiable rules and flags anything that would
ship with a known security hole - inline fix where it can, explicit warning
where it can't.

**Covers:**

| Area | What it checks |
|---|---|
| Row-Level Security | `ENABLE RLS`, `FORCE ROW LEVEL SECURITY`, `USING(true)` trap, partial-op coverage, table-owner bypass |
| Postgres roles | Least-privilege app role, `PUBLIC` schema `CREATE`, `SECURITY DEFINER` + `search_path` |
| SQL injection | Parameterized queries everywhere, including inside `PL/pgSQL EXECUTE` |
| Password hashing | Argon2id (preferred) or bcrypt cost ≥ 12; never `md5()`/`crypt()` in SQL |
| JWTs | Algorithm allowlist server-side; `alg: none` rejected |
| Sessions | `httpOnly` + `Secure` + `SameSite` cookies; not `localStorage` |
| Secret management | No service-role keys in frontend bundles; no secrets in git history |
| Multi-tenancy | RLS-enforced isolation, not just app-layer `WHERE tenant_id = ?` |
| Supply chain | Dependencies pinned and audited |

Built on real research: OWASP Top 10:2025, NIST SP 800-63B, and the
[CVE-2025-48757](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-48757)
case study where 170+ Supabase apps were exposed because RLS was simply
never configured.

---

## Install

### GitHub CLI (recommended)

```bash
# Install into the current project (project scope)
gh skill install maherukhislam/postgres-auth-security-review

# Install globally for all your projects (user scope)
gh skill install maherukhislam/postgres-auth-security-review \
  --scope user

# Target a specific agent
gh skill install maherukhislam/postgres-auth-security-review \
  --agent codex

gh skill install maherukhislam/postgres-auth-security-review \
  --agent claude-code
```

### Manual (copy-paste)

```bash
# Clone and copy into your project's .agents/skills/ folder
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

It exits non-zero if it finds anything, so you can also use it as a CI step:

```yaml
# .github/workflows/security-scan.yml  (add to your own project)
- name: Auth security scan
  run: |
    bash .agents/skills/postgres-auth-security-review/scripts/scan_auth_security.sh .
```

---

## File map

```
skills/
└── postgres-auth-security-review/
    ├── SKILL.md                   # Core rules - what the agent reads when triggered
    ├── references/
    │   └── checklist.md           # Deep reasoning, CVE case study, exact parameters
    └── scripts/
        └── scan_auth_security.sh  # Read-only grep scanner, 7 pattern groups
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
