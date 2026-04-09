---
description: Install leak-guard's pre-push git hook into the current repository
---

Install the leak-guard pre-push hook into `.git/hooks/pre-push` of the current working directory.

Run:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/scanner.py install-githook
```

The command:
- Refuses if cwd is not a git repo
- Backs up an existing `pre-push` hook to `pre-push.leak-guard-backup`
- Copies the template and makes it executable

After install, every `git push` from this repo scans the commits being pushed with `gitleaks` and blocks on findings. To bypass in a genuine emergency: `git push --no-verify` (discouraged — log the reason).
