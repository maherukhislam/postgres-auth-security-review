# Contributing

Contributions are welcome - especially corrections, new CVE coverage, updated
hash parameters, and language-specific scan patterns.

## What's in scope

- New security patterns worth checking for (with a source - CVE, OWASP, NIST,
  or a documented incident)
- Updated parameter recommendations as guidance changes (e.g. bcrypt cost
  floor, Argon2id tuning)
- Additional scan patterns in `scripts/scan_auth_security.sh` for languages
  not yet covered
- Clarifications to `references/checklist.md`

## What's out of scope

- Exploit code or working attack payloads - this skill is defensive only
- Rules so broad they generate constant false positives in the scanner

## Process

1. Fork the repo and create a branch.
2. Make your changes.
3. Run `bash skills/postgres-auth-security-review/scripts/scan_auth_security.sh .`
   to confirm the scanner still works.
4. The CI workflow in `.github/workflows/validate.yml` runs automatically on
   push and PR - make sure it passes before requesting a review.
5. Update `CHANGELOG.md` under an `[Unreleased]` heading.
6. Open a pull request with a short description of what changed and why.

## Updating the skill

Both `SKILL.md` and `references/checklist.md` are plain Markdown - edit them
directly. Keep `SKILL.md` concise (the agent loads it in full when triggered);
move longer reasoning into `references/`. The agentskills.io spec recommends
staying under 500 lines for `SKILL.md`.

## Versioning

This project uses semantic versioning:
- **Patch** (1.0.x): wording fixes, new scan patterns, minor clarifications
- **Minor** (1.x.0): new rule sections, new reference topics
- **Major** (x.0.0): breaking changes to the skill structure or scan script
  interface

After merging, publish a new release with `gh skill publish --tag vX.Y.Z`.
