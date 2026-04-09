---
name: scan-leaks
description: Run leak-guard's local scanner over a file or directory to surface secrets, credentials, and PII. Use before pushing, before sharing logs/exports, or on demand to audit the current workspace.
---

# scan-leaks

Runs the leak-guard scanner locally. Never sends file contents anywhere — the scanner shells out to `gitleaks` and a local regex pack and returns only rule IDs, line numbers, and redacted previews.

## When to use

- Before `git push` (defense in depth on top of the pre-push git hook)
- Before sharing logs, CSVs, exports, or any file outside your machine
- After adding a new dependency or generated code, to catch committed example credentials
- Whenever a teammate asks "is this safe to send?"

## How to run

Invoke `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/scanner.py scan-path <target>` via Bash.

- No argument → scan the current working directory
- File argument → scan that single file
- Directory argument → recursive scan (skips `.git`, `node_modules`, `dist`, `build`, `.next`, `target`)

The command exits `0` on clean, `1` on findings, `2` on error. Summarize the findings for the user — **never quote the raw matched value**; use the redacted preview the scanner returns.

## Output format

```
leak-guard scan: /path/to/target
findings: N
  · [severity] rule-id — description line L in /file [REDACTED:rule:len:hash]
  ...
```

## What to do on findings

1. **Secret / credential / cloud key** → instruct the user to remove from the file and rotate the credential. Do not attempt to fix it silently; rotation is a human decision.
2. **PII** → ask the user whether to redact, replace with a placeholder, or add to `~/.claude/leak-guard/allowlist.toml`.
3. **Sensitive filename** → ask whether to move the file out of the tree or add its path to the allowlist.

## Tuning false positives

User allowlist: `~/.claude/leak-guard/allowlist.toml` (TOML with `literal`, `rule_ids`, `path_globs` arrays). Merged on top of the plugin default. Add entries rather than disabling rules wholesale.
