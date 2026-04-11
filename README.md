# leak-guard

> Local-first PII & secret scanner for Claude Code. Redacts leaks before they reach the model.

[![Version](https://img.shields.io/badge/version-0.5.0-blue)](https://github.com/rinehardramos/leak-guard)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-orange)](https://claude.ai/settings/plugins)

---

## Demo

**On-demand scan** — secrets and PII detected, raw values never shown:

![scan-leaks demo](demo/scan-leaks.gif)

**Hook protocol** — secret redacted in prompt, Claude reports what was caught:

![hook block demo](demo/hook-block.gif)

**Selftest** — 22 internal checks passing:

![selftest demo](demo/selftest.gif)

---

## What it does

Every time you submit a prompt, Claude reads a file, or runs a command — leak-guard scans the content locally for secrets and PII. If something is found, the prompt is **blocked before reaching Anthropic** (exit 2). You see a highlighted preview in your terminal showing exactly what was flagged, then choose:

- **Enter** — redact with semantic `[REDACTED:{type}]` tags and send
- **a** — allow these values (adds to local allowlist) and send original

Raw sensitive values never leave your machine unless you explicitly allow them.

To bypass all findings for a single submission, prefix your prompt with `[allow-once]`.

---

## How it works

```
User prompt submitted
        |
        v
UserPromptSubmit hook fires (before Claude sees it)
        |
        v
scanner.py scans prompt text
        |
    findings?
   /         \
 yes           no
  |             |
Exit 2 (BLOCK)  Pass through unchanged
Show >>>highlighted<<< preview in terminal
        |
  User replies:
  Enter = redact with [REDACTED:{type}] tags
  a     = allow + persist to allowlist
        |
        v
Claude responds with redacted or original prompt
```

All scanning runs 100% locally. No data is sent to any external service.

---

## Detection layers

| Layer | What it catches |
|---|---|
| gitleaks (optional) | AWS/GCP/Azure/GitHub/Stripe/Slack keys, JWTs, private keys, and hundreds of provider-specific patterns |
| Fast regex rules (37 patterns) | Vendor-specific credentials: AWS, GitHub, GitLab, Stripe, Slack, DigitalOcean, Heroku, HashiCorp Vault, Shopify, Square, Telegram, Mailgun, and more |
| DB/URL credential detection | Database connection strings (Postgres, MySQL, MongoDB, Redis, AMQP) and URL-embedded credentials |
| PII regex (20 rules) | Email, SSN, credit card (Luhn-validated), US phone, IBAN, plus international: UK NI, Canadian SIN, Australian TFN, Indian Aadhaar, Mexican CURP, German ID |
| Entropy analysis | High-entropy base64 and hex strings with contextual keyword boosting |
| Fuzzy credential detection | PREFIX:value patterns (e.g. `CSKC:...`) |
| LLM confidence pass | Borderline findings (entropy/fuzzy) are delegated to Claude for contextual judgment — reduces false positives without reducing true positives |
| Claude-as-NER | For long prompts with no regex hits, Claude checks for unstructured PII (names, addresses, medical info) that regex cannot catch |
| Filename blocklist | `.env`, `id_rsa`, `*.pem`, service account files, etc. |

gitleaks is optional — leak-guard warns if it is absent but does not fail. If gitleaks is installed, it provides significantly deeper secret detection.

---

## Hook coverage

| Hook | What it does |
|---|---|
| `UserPromptSubmit` | Scans user prompts; redacts findings before Claude sees them |
| `PreToolUse` | Blocks Bash/Write/Edit calls that contain secrets in their input |
| `PostToolUse` | Scans tool output (Bash stdout, file reads) for secrets/PII |
| `SessionStart` | Scans for sensitive filenames in the working directory |

---

## Installation

**Prerequisites:** Python 3.9+ (system Python is fine). [gitleaks](https://github.com/gitleaks/gitleaks) is optional but recommended for vendor-specific secret patterns (`brew install gitleaks`).

### 1. Install the plugin

```bash
claude plugin install leak-guard@leak-guard
```

### 2. Wire the hooks (one-time setup)

```bash
python3 ~/.claude/plugins/cache/leak-guard/leak-guard/0.3.0/hooks/scanner.py install
```

This single command:
- Syncs the plugin source into the Claude Code cache
- Runs the selftest suite to verify your environment
- Writes all four Claude Code hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SessionStart`) into `~/.claude/settings.json` — idempotently, no duplicates

### 3. Restart Claude Code

Hook changes take effect on the next session start.

---

**Already installed? Re-run step 2** to pick up rule and hook updates after a plugin version upgrade.

---

## Configuration

**Suppress false positives** — create `~/.claude/leak-guard/allowlist.toml`:

```toml
# Exact strings to always allow (placeholder emails, test values, etc.)
literal = ["no-reply@yourcompany.com", "test@example.com"]

# Rule IDs to fully disable
rule_ids = ["us-zip", "ipv4-private"]

# Paths where all rules are suppressed (docs, fixtures, generated files)
path_globs = ["*/docs/*", "*/tests/fixtures/*", "*/README.md"]

# Bash command globs to suppress
bash_globs = ["git log *", "echo *"]
```

Changes apply immediately — no restart needed.

**Add custom detection rules** — create `~/.claude/leak-guard/custom_rules.toml`:

```toml
[[rules]]
id = "my-internal-token"
description = "Internal service token"
pattern = "IST-[A-Z0-9]{32}"
severity = "critical"
```

---

## Commands

### Selftest and scanning

```bash
# Run 22 internal checks (Python version, state dir, rules, gitleaks, hook round-trip)
python3 plugins/leak-guard/hooks/scanner.py selftest

# Scan a file or directory
python3 plugins/leak-guard/hooks/scanner.py scan-path <path>

# Scan stdin
echo "my text" | python3 plugins/leak-guard/hooks/scanner.py scan-text

# Sync plugin to Claude Code cache
python3 plugins/leak-guard/hooks/scanner.py install
```

### Tuning

```bash
# Suppress a false-positive value
python3 plugins/leak-guard/hooks/scanner.py flag fp --literal <value>

# Suppress a rule by ID
python3 plugins/leak-guard/hooks/scanner.py flag fp --suppress-rule <rule_id>

# Add a detection rule
python3 plugins/leak-guard/hooks/scanner.py flag fn --rule-id <id> --pattern <regex>
```

### LLM verifier (opt-in)

```bash
# Enable/disable/check status of LLM cross-check on findings
python3 plugins/leak-guard/hooks/scanner.py verifier enable
python3 plugins/leak-guard/hooks/scanner.py verifier disable
python3 plugins/leak-guard/hooks/scanner.py verifier status
```

### /scan-leaks skill

From within Claude Code chat, run `/scan-leaks` to audit any file or directory on demand.

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
├── .claude-plugin/marketplace.json      <- marketplace catalog
└── plugins/leak-guard/
    ├── .claude-plugin/plugin.json       <- plugin manifest
    ├── hooks/
    │   ├── hooks.json                   <- hook registrations
    │   └── scanner.py                   <- detector engine (stdlib only)
    ├── skills/scan-leaks/SKILL.md       <- /scan-leaks command
    ├── rules/
    │   ├── pii.toml                     <- PII regex pack
    │   ├── filenames.txt                <- sensitive filename blocklist
    │   └── allowlist.toml              <- default suppressions
    └── tests/                           <- pytest suite
```

`scanner.py` is stdlib-only Python. The only optional external binary is `gitleaks`. If gitleaks is absent, leak-guard warns but continues. If the scanner crashes, events are blocked (fail-closed).

---

## Development

```bash
cd ~/Projects/leak-guard

# Internal smoke tests (22 checks)
python3 plugins/leak-guard/hooks/scanner.py selftest

# Full test suite
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Changelog

### v0.5.0 (2026-04-11)
- **Privacy guarantee:** Raw sensitive values never reach Anthropic unless user explicitly allows
- **Block-and-preview:** Hook exits 2 on findings, shows highlighted preview, Enter = redact / a = allow
- **Semantic redaction:** Typed `[REDACTED:{type}]` tags so Claude can reason about the task
- **Symbolic FP reduction:** Borderline findings include metadata (entropy, charset, position) for Claude's judgment — raw value never sent
- **Local NER:** Regex-based name/address/dated-record extraction with context keyword scoring
- **Confidence scoring:** Every finding gets a 0.0-1.0 confidence displayed in preview
- **Feedback loop:** User allow decisions build local FP profile (symbolic only, no raw values)
- **PostToolUse NER:** Tool output scanned for unstructured PII (names near medical/legal keywords)

### v0.4.0 (2026-04-11)
- **Performance:** Normalize text once per scan (was 4x); cache PII rules and filename blocklist by mtime
- **Detection:** +17 fast rules (DB connection strings, URL-embedded creds, Slack webhooks, GitLab, DigitalOcean, Heroku, Discord, Telegram, Mailgun, HashiCorp Vault, Square, Shopify)
- **International PII:** UK National Insurance, Canadian SIN, Australian TFN, Indian Aadhaar, Mexican CURP, German ID (14→20 PII rules)
- **LLM confidence pass:** Borderline findings (entropy/fuzzy) get contextual judgment from Claude instead of hard-blocking — reduces false positives
- **Claude-as-NER:** Long prompts with no regex findings are checked by Claude for unstructured PII (names, addresses, medical info)
- **Bug fix:** `_is_sequential_string` no longer counts cross-class ASCII adjacency (`9:`, `Z[`) as sequential runs

### v0.3.0 (2026-04-10)
- Switched enforcement model: prompt values are redacted inline with `[REDACTED]`; Claude is notified via `additionalContext` SYSTEM NOTE rather than a hard block
- Hook always exits 0 — no prompt suppression
- `[allow-once]` prefix bypasses all findings for one submission
- Expanded selftest to 22 checks (hook round-trip, training pipeline, gitleaks presence)
- Added fuzzy credential detection (PREFIX:value patterns)
- Added entropy analysis for base64/hex strings
- LLM verifier opt-in (`verifier enable/disable/status`)
- `flag fp/fn` commands for in-session tuning
- gitleaks is now optional (WARN not FAIL if absent)

### v0.1.0 (2026-04-09)
- Initial release
- Four hook events: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`
- gitleaks integration for secret/credential/cloud-key detection
- PII regex pack with Luhn credit card validation
- Sensitive filename blocklist
- `/scan-leaks` on-demand skill
- User allowlist (`~/.claude/leak-guard/allowlist.toml`)
- Audit log with redacted previews only
