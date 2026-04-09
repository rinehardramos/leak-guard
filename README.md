# leak-guard

> Local-first PII & secret scanner for Claude Code. Blocks leaks **before they reach the model or a git remote.**

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/rinehardramos/leak-guard)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-orange)](https://claude.ai/settings/plugins)

---

## Demo

**On-demand scan** — secrets and PII detected, raw values never shown:

![scan-leaks demo](demo/scan-leaks.gif)

**Hook protocol** — secret blocked at model boundary, PII surfaces ask dialog:

![hook block demo](demo/hook-block.gif)

**Selftest** — all 11 internal checks passing:

![selftest demo](demo/selftest.gif)

---

## What it does

Every time Claude reads a file, runs a command, or receives your prompt — leak-guard scans the content locally for secrets and PII. If it finds something, it blocks the data from entering the model. The raw value never leaves your machine.

**Secrets** (AWS/GCP/Azure keys, GitHub tokens, private keys, JWTs, …) → **hard block, always.**  
**PII** (email, SSN, phone, credit card, IBAN, DOB, address) → **ask dialog — you decide.**

---

## Three enforcement layers

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Claude Code hooks                                 │
│  UserPromptSubmit → PreToolUse → PostToolUse → SessionStart │
│  Runs before data enters the model context window           │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: /scan-leaks skill                                 │
│  On-demand audit of any file or directory                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: pre-push git hook (per-repo, optional)            │
│  Blocks pushes made outside Claude Code (terminal, CI)      │
└─────────────────────────────────────────────────────────────┘
```

All three layers run **100% locally**. No data is sent to any external service.

---

## Quick install

**Prerequisite — install gitleaks:**
```bash
brew install gitleaks   # macOS
# Linux: https://github.com/gitleaks/gitleaks#installing
```

**Install the plugin:**
```
/plugin marketplace add rinehardramos/leak-guard
/plugin install leak-guard@leak-guard
```

Restart Claude Code. On the next session you'll see:
```
leak-guard v0.1.0 active: hooks armed for secrets + PII.
```

**Optional — protect a git repo from terminal pushes too:**
```
/leak-guard-install-githook
```

---

## What gets detected

| Category | Examples | Action |
|---|---|---|
| AWS credentials | `AKIA…`, `aws_secret_access_key` | Hard block |
| GCP / Azure / GitHub / Stripe / Slack keys | Provider-specific patterns | Hard block |
| Private keys / JWTs | `-----BEGIN RSA PRIVATE KEY-----`, `eyJ…` | Hard block |
| Sensitive filenames | `.env`, `id_rsa`, `*.pem`, `*credentials*.json` | Block Read |
| Email address | `alice@company.com` | Ask dialog |
| US SSN | `123-45-6789` | Ask dialog |
| Credit card (Luhn-validated) | `4242 4242 4242 4242` | Ask dialog |
| US phone | `(555) 867-5309` | Ask dialog |
| IBAN / Passport / DOB / Address | Contextual patterns | Ask dialog |

Secret detection is powered by [gitleaks](https://github.com/gitleaks/gitleaks) — the same engine used in GitHub's secret scanning. PII detection uses a local regex pack with Luhn validation for credit cards.

---

## How the ask dialog works

When PII is found in a `PreToolUse` event (e.g., you ask Claude to write a file containing an email address), Claude Code shows a permission dialog:

```
leak-guard: PII detected in Write input. Allow, deny, or cancel?
  · [low] email — Email address line 3 in <Write-input> [REDACTED:email:17ch:hash=a3f2b1c4]
  To always allow similar: add to ~/.claude/leak-guard/allowlist.toml
```

You choose: **allow** (logged), **deny** (Claude retries differently), or **cancel**.

---

## Tuning false positives

Create `~/.claude/leak-guard/allowlist.toml` to suppress known-safe values:

```toml
# Exact strings to always allow (placeholder emails, test values, etc.)
literal = ["no-reply@yourcompany.com", "test@example.com"]

# Rule IDs to fully disable
rule_ids = ["us-zip", "ipv4-private"]

# Paths where all rules are suppressed (docs, fixtures, generated files)
path_globs = ["*/docs/*", "*/tests/fixtures/*", "*/README.md"]
```

Changes apply immediately — no restart needed.

### Common cases

| Trigger | Fix |
|---|---|
| Your git committer email in `git commit` output | Add your email to `literal` |
| Placeholder emails in docs or READMEs | Add the file path to `path_globs` |
| Test fixtures with synthetic PII | Add `*/tests/fixtures/*` to `path_globs` |
| A noisy rule (e.g. ZIP codes in addresses) | Add the rule ID to `rule_ids` |

---

## Token cost

| Event | Tokens | Frequency |
|---|---|---|
| SessionStart banner | ~80 | once per session |
| Clean tool call | **0** | every call |
| Block / ask on finding | ~100–250 | only when triggered |
| PostToolUse block replacing a leaky file read | **net savings** | only when triggered |

On a clean day: ~80 tokens. Blocking a 3,000-token file read costs ~200 tokens instead — a net saving of ~2,800 tokens.

---

## Audit log

Every decision is logged locally:

```bash
tail -f ~/.claude/leak-guard/audit.log | python3 -m json.tool
```

Raw matched values are never logged — only a SHA-256 prefix and character count.

---

## Architecture

```
leak-guard/
├── .claude-plugin/marketplace.json      ← marketplace catalog
└── plugins/leak-guard/
    ├── .claude-plugin/plugin.json       ← plugin manifest
    ├── hooks/
    │   ├── hooks.json                   ← hook registrations
    │   └── scanner.py                   ← detector engine (stdlib only)
    ├── skills/scan-leaks/SKILL.md       ← /leak-guard:scan-leaks command
    ├── commands/                        ← slash commands (git hook installer)
    ├── rules/
    │   ├── pii.toml                     ← PII regex pack (10 rules)
    │   ├── filenames.txt                ← sensitive filename blocklist
    │   └── allowlist.toml               ← default suppressions
    └── git-hooks/pre-push               ← layer 3 template
```

`scanner.py` is stdlib-only Python. The only external binary dependency is `gitleaks`. Fail-closed: if gitleaks is missing or the scanner crashes, all scanned events are blocked.

---

## Development

```bash
cd ~/Projects/leak-guard

# Internal smoke tests
python3 plugins/leak-guard/hooks/scanner.py selftest

# Full test suite (50 tests)
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Changelog

### v0.1.0 (2026-04-09)
- Initial release
- Four hook events: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`
- gitleaks integration for secret/credential/cloud-key detection
- 10-rule PII regex pack with Luhn credit card validation
- Sensitive filename blocklist (`.env`, `*.pem`, `id_rsa`, service accounts, etc.)
- `/leak-guard:scan-leaks` on-demand skill
- Per-repo pre-push git hook (layer 3)
- User allowlist (`~/.claude/leak-guard/allowlist.toml`)
- Audit log with redacted previews only
- 50-test pytest suite
