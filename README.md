# leak-guard

Local-first PII & secret scanner for [Claude Code](https://claude.com/claude-code). Blocks leaks before they reach the model or a git remote.

## Why

MCP servers cannot prevent data from reaching Anthropic — their tool results are sent back to Claude as context. leak-guard uses **Claude Code hooks**, which run locally and gate content at the boundary, plus a per-repo **pre-push git hook** for pushes that happen outside Claude Code.

## Three layers

| Layer | What it protects | Mechanism |
|---|---|---|
| 1. Claude Code hooks | Data flowing into the model | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` hooks scan prompts, tool inputs, and tool outputs. Secrets hard-block. PII asks by default. |
| 2. `/scan-leaks` skill | On-demand audit | Runs the same scanner over a file or directory. Returns rule IDs + redacted previews, never raw values. |
| 3. Pre-push git hook | Pushes made outside Claude Code (terminal, IDE, CI) | Installed per-repo. Runs `gitleaks` on the commits being pushed. Blocks on secrets. |

All three layers run **100% locally** and never transmit scanned content anywhere.

## Detection

- **Secrets / credentials / cloud keys** — [`gitleaks`](https://github.com/gitleaks/gitleaks) (default rule pack: AWS, GCP, Azure, GitHub, Stripe, Slack, JWT, private keys, etc.)
- **PII** — regex pack: email, US phone, SSN, credit card (Luhn-validated), IBAN, passport, DOB, street address, ZIP, IPv4
- **Sensitive filenames** — `.env*`, `*.pem`, `id_rsa*`, `*credentials*.json`, `*service-account*.json`, etc.

## Install

### Prerequisite

```bash
brew install gitleaks   # macOS
# or: https://github.com/gitleaks/gitleaks#installing
```

If `gitleaks` is missing, leak-guard **fails closed** — every scanned event is blocked until it's installed. This is intentional.

### Claude Code plugin

```
/plugin marketplace add rinehardramos/leak-guard
/plugin install leak-guard@leak-guard
```

Restart Claude Code. On the next session you'll see a `leak-guard v0.1.0 active` banner.

### Per-repo pre-push hook (layer 3)

From inside any git repo you want to protect:

```
/leak-guard-install-githook
```

This copies a pre-push hook into `.git/hooks/pre-push`. It's a standard git hook — it runs on every `git push` whether or not Claude Code is involved. To bypass in a genuine emergency: `git push --no-verify` (logged, discouraged).

## Behavior

### Secrets → hard block
Real credentials are never allowed through, even with user consent. Rotate the key; removing it from the file is not sufficient if the model or a remote already saw it.

### PII → ask (tuned) / redact (once stable)
On PII detection, `PreToolUse` returns `permissionDecision: "ask"` with a redacted preview and a choice. **Current default is `ask`.** Once you've tuned the allowlist, you can switch the default to silent `redact` by editing `scanner.py` (see roadmap).

### Known protocol limitation
Claude Code's `PostToolUse` hook cannot modify tool results for non-MCP tools — only block them. That means:

- **`Read` on a file containing secrets** → PostToolUse blocks the tool result entirely. Claude sees only the block reason + redacted summary, not the file content. The raw bytes never enter the context.
- leak-guard cannot "redact in place" and let Claude see a cleaned version. If you need that, move the secret out of the file, then re-run.

### UserPromptSubmit: block-only
`UserPromptSubmit` doesn't support `ask` — only allow or block. If leak-guard detects PII in your typed prompt, it blocks with a reason and you rephrase.

## Tuning false positives

User allowlist: `~/.claude/leak-guard/allowlist.toml`

```toml
literal = ["jane@example.com", "555-0100"]
rule_ids = ["us-zip", "ipv4-private"]
path_globs = ["*/tests/fixtures/*", "*/docs/examples/*"]
```

The user allowlist is merged on top of the plugin's default ([`rules/allowlist.toml`](plugins/leak-guard/rules/allowlist.toml)). Rules loaded from the plugin default include `us-zip` and `ipv4-private` as disabled by default — they're too noisy on code.

To add or tighten PII rules, edit `rules/pii.toml` in your plugin cache or fork the repo. Each rule is one TOML table.

## Audit log

Every block, ask, and error is logged to `~/.claude/leak-guard/audit.log` (newline-delimited JSON). Matched values are never logged raw — only a short SHA256 prefix.

```bash
tail -f ~/.claude/leak-guard/audit.log
```

## Uninstall

```
/plugin uninstall leak-guard@leak-guard
```

For the per-repo git hook:

```bash
rm .git/hooks/pre-push
# restore any backup if needed:
mv .git/hooks/pre-push.leak-guard-backup .git/hooks/pre-push
```

## Token cost

leak-guard's hooks run locally and consume **zero tokens** on clean events. Scanning, gitleaks, rule loading — all local.

Tokens are only used when leak-guard needs to tell Claude something:

| Event | Cost | Frequency |
|---|---|---|
| `SessionStart` banner | ~80 tok | once per session |
| Clean `PreToolUse` pass | 0 | every tool call |
| `PreToolUse` deny/ask (on hit) | ~80–250 tok | only on findings |
| `PostToolUse` block replacing a 3k-token file read | **net –2800 tok** | only on hit |

Expected overhead on a clean day: ~80 tokens. On a hit-heavy day: low thousands. For file reads that would have returned a leaky file, leak-guard is a **token savings** vs. letting it through.

## Architecture

```
~/Projects/leak-guard/                    (this repo = marketplace)
├── .claude-plugin/marketplace.json
└── plugins/leak-guard/
    ├── .claude-plugin/plugin.json
    ├── hooks/
    │   ├── hooks.json                    hook registrations
    │   └── scanner.py                    single entry point, stdlib only
    ├── skills/scan-leaks/SKILL.md        /scan-leaks command
    ├── commands/                         slash commands (installer)
    ├── rules/                            pii.toml, filenames.txt, allowlist.toml
    ├── git-hooks/pre-push                installable layer 3
    └── ...
```

Scanner entry points (all via `python3 scanner.py <subcmd>`):

- `hook-user-prompt`, `hook-pre-tool`, `hook-post-tool`, `hook-session-start` — hook events
- `scan-path <path>` — on-demand scan (used by `/scan-leaks`)
- `scan-text` — scan stdin (for shell integrations)
- `install-githook` — copies pre-push into `.git/hooks/`
- `git-hook-pre-push` — invoked by the pre-push hook itself
- `selftest` — smoke tests for rules and gitleaks integration

Fail-closed: any uncaught exception in a hook path produces a block decision, not a pass.

## Development

```bash
cd ~/Projects/leak-guard
python3 plugins/leak-guard/hooks/scanner.py selftest
pytest tests/
```

Add the marketplace locally for testing:

```
/plugin marketplace add ~/Projects/leak-guard
/plugin install leak-guard@leak-guard
```

## License

MIT — see [LICENSE](LICENSE).
