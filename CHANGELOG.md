# Changelog

All notable changes to leak-guard are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.0] — 2026-04-09

This release is a significant hardening and intelligence update. It fixes real
security vulnerabilities in the tool itself, cuts false positives substantially,
and introduces an opt-in LLM cross-check flow — all without making any network
calls or sending any user content outside the local machine.

### Security fixes

Eight audit findings addressed:

| ID  | Severity | Fix |
|-----|----------|-----|
| C02 | Critical | `[allow-once]` prefix now only bypasses heuristic findings. Definitive secrets (confirmed AWS keys, GitHub PATs, Stripe keys, etc.) block unconditionally even when the prefix is present. |
| C01 | Critical | Git pre-push SHAs validated against `[0-9a-f]{40}` before being used in gitleaks `--log-opts`. Crafted push stdin could previously smuggle extra git-log flags. |
| H02 | High | NFKC Unicode normalization + bidi/zero-width character stripping applied before all four scan functions. Closes homoglyph and zero-width evasion paths (adversarial tests H02, J10 now correctly handled). |
| H05 | High | State directory created with `mode=0o700`; `audit.log` and config files with `0o600`. Existing installations upgraded on first run. Previously world-readable on default macOS umask. |
| H03 | High | `sys.stdin.read()` capped at 4 MB in `read_event()`, `cmd_scan_text()`, and the git pre-push hook. Removes OOM/CPU DoS vector from large tool outputs. |
| M04 | Medium | Malformed hook event JSON now fails closed (raises `ValueError` → outer handler emits block) instead of silently returning an empty dict and allowing. |
| M06 | Medium | Internal exception details no longer emitted to Claude's context. Generic message shown; full `str(e)` written only to the local audit log. |
| M07 | Medium | Removed credential-label words (`token`, `secret`, `apikey`, `api_key`, etc.) from `_KNOWN_DUMMY_VALUES`. These are labels, not placeholder values, and their presence was suppressing detection of any credential whose normalized value matched them. |

### Added

**Dummy-value false-positive suppression (`_is_dummy_value`)**

A new `_is_dummy_value()` helper eliminates the most common class of false
positives — prompts like `password=helloworld` or `api_key=<YOUR_API_KEY_HERE>`
that look like assignments but contain obvious placeholders.

- `_KNOWN_DUMMY_VALUES` frozenset (~50 entries): canonical weak passwords
  (`helloworld`, `changeme`, `hunter2`, `letmein`, `password123`…), generic
  placeholders (`foo`, `bar`, `test`, `example`, `demo`…), and common English
  label words that appear as RHS values in documentation (`prefix`, `suffix`,
  `context`, `value`, `format`, `mode`…).
- `_PLACEHOLDER_SHAPE_RE`: structural placeholder patterns — `<YOUR_KEY>`,
  `{{API_KEY}}`, `${TOKEN}`, `$SECRET_KEY`.
- Single-character runs (`xxxxxxxx`, `00000000`, `********`) suppressed.
- 40-character all-hex strings recognized as git commit SHAs and suppressed.
- Applied in `scan_entropy` (candidate value), `scan_fuzzy_credentials`
  (value after prefix), and `scan_pii_text` (RHS after `=/:`).

**`bash_globs` allowlist field**

New `bash_globs` array in `~/.claude/leak-guard/allowlist.toml`. When a
`Bash` tool PostToolUse event's command matches any glob, output scanning
is skipped entirely. Useful for pentest runners, git log commands, and other
tools whose output contains intentional secret-shaped strings.

```toml
bash_globs = [
    "*git log*",
    "*git tag*",
    "*tests/adversarial*",
]
```

Falls back to the source label string if `tool_input["command"]` is absent
from the PostToolUse event (which Claude Code omits in some versions).

**Opt-in LLM verifier (`scanner.py verifier`)**

An interactive cross-check flow that lets the active Claude session verify
whether a blocked string is genuinely a secret — without any API calls and
without sending any real user content anywhere.

```
# Opt in (shown once, explains exactly what it does)
scanner.py verifier enable

# After a block, the block message includes:
#   ↳ [verifier] Cross-check available — run: scanner.py verify-emit lg-1744156800-a3f2

# Emit a paste-able synthetic prompt (no real content, deterministic from rule shape)
scanner.py verify-emit lg-1744156800-a3f2

# After pasting into Claude and reading the classification:
scanner.py verify-ingest lg-1744156800-a3f2 SECRET

# Check/disable
scanner.py verifier status
scanner.py verifier disable
```

How it works:
1. On block: generates a correlation ID (`lg-<timestamp>-<4hex>`), writes
   a metadata-only entry to `~/.claude/leak-guard/pending_verifications.jsonl`
   (rule ID, category, shape — **no user content**).
2. `verify-emit`: generates 3 synthetic strings from the rule's canonical
   character shape using a deterministic seed (`random.Random(hash(id))`).
   Shape mappings: `aws-access-token` → `AKIA`+16 alphanum; `github-pat` →
   `ghp_`+36 alphanum; `stripe` → `sk_live_`+24; `slack` → `xoxb-…`;
   `jwt` → `eyJ…`; fuzzy-prefix → `ORG:`+mixed; entropy → base64 blob.
   PII rules (SSN, credit card, phone) are skipped — pattern-based rules
   gain nothing from model classification.
3. `verify-ingest`: records verdict, appends to `verifier_feedback.jsonl`
   for surfacing in the `--review` interactive flow.

New state files (all in `~/.claude/leak-guard/`):

| File | Contents |
|------|----------|
| `verifier.toml` | Opt-in flag |
| `pending_verifications.jsonl` | Correlation IDs + rule metadata (no user content) |
| `verifier_feedback.jsonl` | Ingested verdicts for the review flow |

**`scanner.py install` subcommand**

Automates syncing the plugin source into the Claude Code plugin cache
(`~/.claude/plugins/cache/`). Previously, edits to the dev source had no
effect until the cache was manually updated.

```bash
python3 plugins/leak-guard/hooks/scanner.py install
```

- Auto-discovers the cache root: checks `__file__` first (if already
  running from cache), then falls back to a glob over the cache directory.
- Mirrors all files from the source plugin root, skipping `__pycache__`,
  `.pyc`, `.git`, and `.claude-plugin` metadata.
- Creates a `.bak` backup of each existing file before overwriting.
- Preserves executable bits on all copied files.
- Runs `selftest` on the newly installed copy and prints a restart reminder.

**Pentest suite improvements**

- `tests/adversarial_suite.py --review`: interactive yes/no triage for
  FP/FN/UNCERTAIN items. Calls `scanner.py flag` internally — no copy-pasting.
- FP flow: auto-extracts longest token, one keystroke to allowlist.
- FN flow: prompts for `rule_id` + regex, creates custom rule entry.
- UNCERTAIN flow: asks "was blocking correct?" and routes accordingly.

### Changed

- `hook_user_prompt`, `hook_pre_tool`, `hook_post_tool`: block messages now
  include the verifier notice line when verifier is enabled.
- `Allowlist` dataclass: new `bash_globs: list[str]` field.
- `load_allowlist()`: reads `bash_globs` from both default and user TOML files.

### Fixed

- **Critical: `hook_user_prompt` exit-code enforcement.** All three block
  branches (`definitive_secrets`, `heuristic_findings`, `definitive_pii`)
  previously returned exit 0. Claude Code only enforces a `UserPromptSubmit`
  block when the hook exits with code 2 — exit 0 silently allows the prompt
  through regardless of the JSON payload. Fixed: all block paths now
  `return 2`; `main()` fail-closed handler likewise emits exit 2 for
  `hook-user-prompt` and `hook-pre-tool` (PostToolUse stays 0, as its block
  is advisory via stdout JSON).
- `hook_post_tool`: PostToolUse on `Read` tool now correctly honours
  `path_globs` before scanning output (was only checked in PreToolUse).
- `silent_blocks` allowlist flag now suppresses stderr notifications
  consistently across all three hook handlers.

### Pentest results (v0.2.0 baseline)

100 adversarial prompts across 10 categories (A–J):

| Metric | Count |
|--------|-------|
| True Positives (caught real secrets) | 74 |
| True Negatives (clean prompts passed) | 13 |
| False Negatives (missed secrets) | 0 |
| False Positives (noise) | 3 |
| Uncertain (no ground truth set) | 10 |

Remaining FPs: `B03` (email address alone), `G07` (high-entropy string
with no context keyword), `H02` (zero-width space evasion — correctly
handled by NFKC normalization; expected label not yet updated in corpus).

---

## [0.1.0] — 2026-03-xx

Initial release.

### Added

- Claude Code hook integration: `UserPromptSubmit`, `PreToolUse`,
  `PostToolUse`, `SessionStart`.
- Secret detection via gitleaks (19 rule classes: AWS, GitHub, Stripe,
  Slack, Anthropic, OpenAI, JWT, and more).
- Heuristic detection: Shannon entropy scanner for base64 and hex tokens
  with context-keyword reduction (`secret`, `token`, `password`, `pwd`,
  `sk`, `pat`, abbreviations).
- Fuzzy credential detection: `PREFIX:value` pattern matching for custom
  credential formats (catches `CSKC:…`, `MYAPP:…`, `SDK:…`, etc.).
- PII detection: SSN, credit card (Luhn-validated), phone, email via
  configurable `rules/pii.toml`.
- Filename blocklist: blocks reads of `.env`, `id_rsa`, `*.pem`, etc.
  before content reaches Claude's context.
- Allowlist: `~/.claude/leak-guard/allowlist.toml` with `literal`,
  `rule_ids`, `path_globs`, `silent_blocks` fields.
- Custom rules: `~/.claude/leak-guard/custom_rules.toml` with `pattern`,
  `context_keyword`, `fuzzy_prefix` sections.
- `scanner.py flag fp/fn` CLI for learning-loop feedback:
  allowlist a literal, suppress a rule, or add a custom regex.
- `scanner.py selftest`: 11 self-verification checks.
- `scanner.py scan-path / scan-text`: manual scanning outside hooks.
- Git pre-push hook: scans staged commits via gitleaks before push.
- `tomli` vendor bundle for Python < 3.11 compatibility.
- Audit log: append-only JSONL at `~/.claude/leak-guard/audit.log`.

---

[0.2.0]: https://github.com/rinehardramos/leak-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rinehardramos/leak-guard/releases/tag/v0.1.0
