# Training Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an author-only training mode that logs every scanner finding, lets the author label FP/FN/Unclear, runs LLM analysis to categorize and weight each finding, and auto-promotes high-confidence findings into the shared ruleset committed to the repo for marketplace publishing.

**Architecture:** Three-phase pipeline:
1. **Capture** — every finding writes a `training_log.jsonl` entry (author machine only, detected via `LEAK_GUARD_AUTHOR=1` env var set in author's shell)
2. **Analyze** — `train analyze` sends unlabelled or user-labelled entries through Claude (reusing the existing verifier `verify-emit`/`verify-ingest` pattern) to produce a category + confidence weight
3. **Promote** — `train promote` takes high-confidence findings and writes them into `plugins/leak-guard/rules/` TOML/txt files in the repo, ready to commit and publish

**Tech Stack:** Python stdlib only for capture/promote. Existing verifier hook pattern for LLM analysis. JSONL for training log. TOML/txt for rule promotion targets.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `plugins/leak-guard/hooks/scanner.py` | Modify | Add `TRAINING_LOG`, `_write_training_entry()`, `cmd_train()`, `train` subparser, `_train_analyze()`, `_train_promote()` |
| `~/.claude/leak-guard/training_log.jsonl` | Runtime-created | Per-finding records with verdict + analysis fields |
| `plugins/leak-guard/rules/pii.toml` | Modify (promote step) | New PII patterns promoted from training |
| `plugins/leak-guard/rules/allowlist.toml` | Modify (promote step) | FP suppress_rules promoted from training |
| `plugins/leak-guard/rules/filenames.txt` | Modify (promote step) | New filename patterns promoted from training |
| `tests/test_scanner.py` | Modify | `TestTrainingMode` covering capture, verdict, list, analyze, promote |

---

## Task 1: Author detection + training log capture

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py`
- Modify: `tests/test_scanner.py`

Author mode is detected via `LEAK_GUARD_AUTHOR=1` in the environment. This is set in the author's `~/.zshrc` / `~/.zprofile` — no other machine has it. No config file, no toggle, no UI.

- [ ] **Step 1: Write the failing test**

Add at the bottom of `tests/test_scanner.py`:

```python
class TestTrainingMode:
    def test_capture_skipped_without_author_flag(self, tmp_path):
        """Without LEAK_GUARD_AUTHOR=1, no training_log.jsonl is written."""
        cred = "CSKC:Scds" + "JCCKLSLKDKLCNLKCEINK2233as"
        env = {k: v for k, v in os.environ.items() if k != "LEAK_GUARD_AUTHOR"}
        env["LEAK_GUARD_STATE_DIR"] = str(tmp_path)
        import subprocess
        r = subprocess.run(
            [sys.executable, str(SCANNER), "hook-user-prompt"],
            input=json.dumps({"hook_event_name": "UserPromptSubmit",
                              "prompt": f"my key {cred}",
                              "session_id": "train-test"}),
            capture_output=True, text=True, env=env, timeout=30,
        )
        log = tmp_path / "training_log.jsonl"
        assert not log.exists(), "training_log.jsonl must NOT be written without LEAK_GUARD_AUTHOR=1"

    def test_capture_written_with_author_flag(self, tmp_path):
        """With LEAK_GUARD_AUTHOR=1, training_log.jsonl is written per finding."""
        cred = "CSKC:Scds" + "JCCKLSLKDKLCNLKCEINK2233as"
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1"}
        import subprocess
        r = subprocess.run(
            [sys.executable, str(SCANNER), "hook-user-prompt"],
            input=json.dumps({"hook_event_name": "UserPromptSubmit",
                              "prompt": f"my key {cred}",
                              "session_id": "train-test"}),
            capture_output=True, text=True, env=env, timeout=30,
        )
        log = tmp_path / "training_log.jsonl"
        assert log.exists(), "training_log.jsonl should be written when LEAK_GUARD_AUTHOR=1"
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert len(entries) >= 1
        e = entries[0]
        assert e["verdict"] == "pending"
        assert "hash" in e
        assert "raw_match" not in e
        assert "ts" in e
        assert "session_id" in e
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /Users/rinehardramos/Projects/leak-guard
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode -v
```
Expected: both `FAILED` — `TRAINING_LOG` and `_write_training_entry` don't exist yet.

- [ ] **Step 3: Add constants and author check**

Find `AUDIT_LOG = _STATE_DIR / "audit.log"` and add after it:

```python
TRAINING_LOG = _STATE_DIR / "training_log.jsonl"


def _author_mode() -> bool:
    """True only on the author's machine — gated by LEAK_GUARD_AUTHOR=1 env var.
    Set this in ~/.zshrc: export LEAK_GUARD_AUTHOR=1
    Other users never have this set, so training capture is a no-op for them.
    """
    return os.environ.get("LEAK_GUARD_AUTHOR") == "1"
```

- [ ] **Step 4: Implement `_write_training_entry()`**

Add after the `audit()` function:

```python
def _write_training_entry(findings: list, session_id: str = "") -> None:
    """Author-only: append one JSONL line per finding. No raw values stored."""
    if not _author_mode():
        return
    try:
        ensure_state_dir()
        ts = time.time()
        lines = []
        for f in findings:
            entry = {
                "ts": ts,
                "session_id": session_id,
                "verdict": "pending",       # user labels later via train verdict
                "analysis": None,           # filled by train analyze
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "hash": sha256(f.raw_match) if f.raw_match else "",
                "preview": f.preview,       # already redacted by redact_preview()
                "source": f.source,
            }
            lines.append(json.dumps(entry, default=str))
        with TRAINING_LOG.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        pass
```

- [ ] **Step 5: Call in `hook_user_prompt()`**

Read `session_id` at the top of `hook_user_prompt()`:

```python
def hook_user_prompt() -> int:
    event = read_event()
    prompt = event.get("prompt", "") or ""
    session_id = event.get("session_id", "")   # ADD
```

After `audit("redact_user_prompt", {"count": len(findings)})`:

```python
    audit("redact_user_prompt", {"count": len(findings)})
    _write_training_entry(findings, session_id=session_id)   # ADD
    summary = format_summary(findings)
```

- [ ] **Step 6: Run tests**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode -v
```
Expected: both `PASSED`.

- [ ] **Step 7: Commit**

```bash
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): author-only capture — write training_log.jsonl when LEAK_GUARD_AUTHOR=1"
```

---

## Task 2: `train verdict` — manual labelling

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py`
- Modify: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add inside `TestTrainingMode`:

```python
    def test_verdict_updates_pending_entry(self, tmp_path):
        import subprocess
        log = tmp_path / "training_log.jsonl"
        fake_hash = "abcd1234efgh5678"
        entry = {"ts": 1000.0, "session_id": "s1", "verdict": "pending", "analysis": None,
                 "rule_id": "fuzzy-prefixed-credential", "category": "secret",
                 "severity": "high", "hash": fake_hash,
                 "preview": "[REDACTED:fuzzy:8ch:hash=abcd1234]", "source": "<test>"}
        log.write_text(json.dumps(entry) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1"}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "verdict", fake_hash, "fp"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        updated = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert updated[0]["verdict"] == "fp"
        assert "verdict_ts" in updated[0]
```

- [ ] **Step 2: Run to verify failure**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_verdict_updates_pending_entry -v
```
Expected: `FAILED` — `train` subcommand does not exist.

- [ ] **Step 3: Implement `_VALID_VERDICTS`, `cmd_train()`, `_train_verdict()`**

Add after `cmd_flag()`:

```python
_VALID_VERDICTS = {"fp", "fn", "unclear", "confirm"}


def cmd_train(args) -> int:
    """Author-only training mode commands."""
    if not _author_mode() and args.train_cmd not in ("list",):
        print("train: requires LEAK_GUARD_AUTHOR=1 (author-only feature)", file=sys.stderr)
        return 2
    dispatch = {
        "verdict": lambda: _train_verdict(args.hash_prefix, args.verdict),
        "list":    lambda: _train_list(args.filter),
        "analyze": lambda: _train_analyze(),
        "promote": lambda: _train_promote(args.dry_run),
    }
    fn = dispatch.get(args.train_cmd)
    if fn is None:
        print(f"train: unknown subcommand '{args.train_cmd}'", file=sys.stderr)
        return 2
    return fn()


def _train_verdict(hash_prefix: str, verdict: str) -> int:
    if verdict not in _VALID_VERDICTS:
        print(f"train verdict: must be one of {sorted(_VALID_VERDICTS)}", file=sys.stderr)
        return 2
    if not TRAINING_LOG.exists():
        print("train verdict: no training_log.jsonl found — run the scanner first", file=sys.stderr)
        return 1
    entries, updated = [], 0
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries.append(line)
            continue
        if e.get("hash", "").startswith(hash_prefix) and e.get("verdict") == "pending":
            e["verdict"] = verdict
            e["verdict_ts"] = time.time()
            updated += 1
        entries.append(json.dumps(e, default=str))
    TRAINING_LOG.write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(f"train verdict: updated {updated} entry/entries to '{verdict}'")
    audit("train_verdict", {"hash_prefix": hash_prefix, "verdict": verdict, "updated": updated})
    return 0 if updated > 0 else 1
```

- [ ] **Step 4: Wire `train` into argparse in `main()`**

After `sub.add_parser("selftest")`:

```python
    tp = sub.add_parser("train", help="[author] Training pipeline: verdict/list/analyze/promote")
    train_sub = tp.add_subparsers(dest="train_cmd", required=True)

    tv = train_sub.add_parser("verdict", help="Label a finding by hash prefix")
    tv.add_argument("hash_prefix")
    tv.add_argument("verdict", choices=sorted(_VALID_VERDICTS))

    tl = train_sub.add_parser("list", help="List training log entries")
    tl.add_argument("--filter", choices=["pending","fp","fn","unclear","confirm","all"],
                    default="pending")

    train_sub.add_parser("analyze", help="LLM-analyze unlabelled entries to assign category+weight")

    tpr = train_sub.add_parser("promote", help="Write high-confidence findings into repo rules")
    tpr.add_argument("--dry-run", action="store_true")
```

Dispatch in `main()`:

```python
        elif args.cmd == "train":
            return cmd_train(args)
```

- [ ] **Step 5: Run test**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_verdict_updates_pending_entry -v
```

- [ ] **Step 6: Commit**

```bash
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): add 'train verdict' for FP/FN/unclear/confirm labelling"
```

---

## Task 3: `train list` — review the log

- [ ] **Step 1: Write the failing test**

```python
    def test_list_filters_by_verdict(self, tmp_path):
        import subprocess
        log = tmp_path / "training_log.jsonl"
        entries = [
            {"ts": 1000.0, "verdict": "pending", "rule_id": "fuzzy-prefixed-credential",
             "hash": "aabbcc11", "preview": "[REDACTED:8ch]", "source": "<test>", "session_id": "s1", "analysis": None},
            {"ts": 2000.0, "verdict": "fp", "rule_id": "email",
             "hash": "ddeeff22", "preview": "a@b.com", "source": "<test>", "session_id": "s2", "analysis": None},
        ]
        log.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "list", "--filter", "pending"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0
        assert "aabbcc11" in r.stdout
        assert "ddeeff22" not in r.stdout
```

- [ ] **Step 2: Run to verify failure**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_list_filters_by_verdict -v
```

- [ ] **Step 3: Implement `_train_list()`**

```python
def _train_list(filter_verdict: str = "pending") -> int:
    if not TRAINING_LOG.exists():
        print("train list: no training_log.jsonl found")
        return 0
    entries = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    shown = [e for e in entries
             if filter_verdict == "all" or e.get("verdict") == filter_verdict]
    if not shown:
        print(f"train list: no entries with verdict='{filter_verdict}'")
        return 0
    print(f"{'#':<4} {'verdict':<10} {'analysis':<12} {'rule_id':<35} {'hash':<18} preview")
    print("-" * 100)
    for i, e in enumerate(shown):
        ana = (e.get("analysis") or {}).get("category", "-") if e.get("analysis") else "-"
        print(f"{i+1:<4} {e.get('verdict','?'):<10} {ana:<12} {e.get('rule_id','?'):<35} "
              f"{e.get('hash','?')[:16]:<18} {e.get('preview','')}")
    print(f"\n{len(shown)} entry/entries.")
    return 0
```

- [ ] **Step 4: Run + commit**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_list_filters_by_verdict -v
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): add 'train list' to review captured findings"
```

---

## Task 4: `train analyze` — LLM categorization and weighting

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py`
- Modify: `tests/test_scanner.py`

This reuses the existing `verify-emit` / `verify-ingest` pattern. `train analyze` emits an `additionalContext` prompt asking Claude to assess each pending/unclear/fn entry — Claude responds inline, then `verify-ingest` records the verdict. For training, we use a dedicated `train-analysis` prompt format.

The analysis produces a structured response per finding:
```
ANALYSIS:<hash>:category=<secret|pii|benign>:confidence=<0.0-1.0>:reason=<one line>
```

- [ ] **Step 1: Write the failing test**

```python
    def test_analyze_emits_additionalContext(self, tmp_path):
        """train analyze emits a SYSTEM NOTE asking Claude to categorize findings."""
        import subprocess
        log = tmp_path / "training_log.jsonl"
        entry = {"ts": 1000.0, "verdict": "unclear", "analysis": None,
                 "rule_id": "high-entropy-base64", "category": "secret", "severity": "high",
                 "hash": "aabb1122ccdd3344", "preview": "[REDACTED:entropy:12ch:hash=aabb1122]",
                 "source": "<test>", "session_id": "s1"}
        log.write_text(json.dumps(entry) + "\n")
        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1"}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "analyze"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout) if r.stdout.strip() else {}
        ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "ANALYSIS" in ctx or "categorize" in ctx.lower()
        assert "aabb1122" in ctx   # hash present so Claude can reference it
```

- [ ] **Step 2: Run to verify failure**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_analyze_emits_additionalContext -v
```

- [ ] **Step 3: Implement `_train_analyze()`**

```python
def _train_analyze() -> int:
    """Emit an additionalContext prompt asking Claude to categorize pending/unclear/fn findings.
    Claude's response is then ingested via 'train ingest-analysis' on the next turn.
    """
    if not TRAINING_LOG.exists():
        print("train analyze: no training_log.jsonl found", file=sys.stderr)
        return 1

    candidates = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Analyze entries that are pending, unclear, or user-flagged fn but not yet analyzed
        if e.get("verdict") in ("pending", "unclear", "fn") and e.get("analysis") is None:
            candidates.append(e)

    if not candidates:
        print("train analyze: no unanalyzed entries found (run scanner to capture findings first)")
        return 0

    lines = [
        "SYSTEM NOTE (leak-guard training): Analyze each finding below.",
        "For each, respond on ONE line exactly:",
        "  ANALYSIS:<hash>:category=<secret|pii|benign>:confidence=<0.00-1.00>:reason=<one sentence>",
        "",
        "Rules:",
        "- secret: any credential, token, API key, password, private key",
        "- pii: personally identifiable info (email, SSN, phone, etc.) but not a credential",
        "- benign: internal ID, UUID, hash, random string with no credential semantics",
        "- confidence: 0.0=certainly benign, 1.0=certainly a real credential/PII leak",
        "- Weight toward the finding being a real leak if ambiguous (conservative scanner policy)",
        "",
        "Findings to analyze:",
    ]
    for e in candidates[:20]:   # cap at 20 per turn
        lines.append(f"  hash={e['hash']} rule={e['rule_id']} preview={e['preview']} "
                     f"user_verdict={e['verdict']}")

    lines += [
        "",
        "After responding with ANALYSIS lines, call: scanner.py train ingest-analysis",
        "(This will be done automatically on the next hook turn.)",
    ]

    ctx = "\n".join(lines)
    out = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ctx}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    audit("train_analyze", {"count": len(candidates)})
    return 0
```

- [ ] **Step 4: Implement `_train_ingest_analysis()` and `train ingest-analysis` subcommand**

This reads Claude's ANALYSIS responses from stdin (passed as a text block) and updates `training_log.jsonl`:

```python
_ANALYSIS_RE = re.compile(
    r"ANALYSIS:(?P<hash>[a-f0-9]+):category=(?P<category>secret|pii|benign)"
    r":confidence=(?P<conf>[0-9.]+):reason=(?P<reason>.+)"
)


def _train_ingest_analysis(text: str) -> int:
    """Parse ANALYSIS lines from Claude's response and update training_log.jsonl."""
    if not TRAINING_LOG.exists():
        print("train ingest-analysis: no training_log.jsonl found", file=sys.stderr)
        return 1

    parsed = {}
    for line in text.splitlines():
        m = _ANALYSIS_RE.search(line.strip())
        if m:
            h = m.group("hash")
            parsed[h] = {
                "category": m.group("category"),
                "confidence": float(m.group("conf")),
                "reason": m.group("reason").strip(),
                "analyzed_ts": time.time(),
            }

    if not parsed:
        print("train ingest-analysis: no valid ANALYSIS lines found in input", file=sys.stderr)
        return 1

    entries, updated = [], 0
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries.append(line)
            continue
        h = e.get("hash", "")
        match = next((v for k, v in parsed.items() if h.startswith(k) or k.startswith(h)), None)
        if match:
            e["analysis"] = match
            updated += 1
        entries.append(json.dumps(e, default=str))

    TRAINING_LOG.write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(f"train ingest-analysis: updated {updated} entry/entries with LLM analysis")
    audit("train_ingest_analysis", {"parsed": len(parsed), "updated": updated})
    return 0
```

Add `ingest-analysis` to the argparse `train_sub`:

```python
    ia = train_sub.add_parser("ingest-analysis",
                               help="Ingest Claude's ANALYSIS responses into training log")
    ia.add_argument("--text", default=None,
                    help="ANALYSIS text (reads stdin if omitted)")
```

Wire in `cmd_train()`:

```python
        "ingest-analysis": lambda: _train_ingest_analysis(
            args.text if args.text else sys.stdin.read()
        ),
```

- [ ] **Step 5: Run full suite**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py -q
```

- [ ] **Step 6: Commit**

```bash
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): add 'train analyze' + 'train ingest-analysis' — LLM categorization and weighting"
```

---

## Task 5: `train promote` — write into shared ruleset

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py`
- Modify: `plugins/leak-guard/rules/allowlist.toml` (at promote time)
- Modify: `plugins/leak-guard/rules/pii.toml` (at promote time)

Promotion criteria (all must be true):
- `analysis.confidence >= 0.75`
- `analysis.category` in `("secret", "pii")`
- `verdict` in `("fn", "unclear", "confirm", "pending")` — NOT `"fp"` (FPs go to allowlist suppression instead)

FPs with `confidence >= 0.75` are promoted as `suppress_rules` into `plugins/leak-guard/rules/allowlist.toml`.

- [ ] **Step 1: Write the failing test**

```python
    def test_promote_fn_writes_to_rules(self, tmp_path):
        """High-confidence FN entries are promoted as pii.toml pattern candidates."""
        import subprocess
        # Simulate repo rules dir
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "pii.toml").write_text("# patterns\n[[pattern]]\nrule_id = \"existing\"\n")
        (rules_dir / "allowlist.toml").write_text("suppress_rules = {}\n")

        log = tmp_path / "training_log.jsonl"
        entry = {
            "ts": 1000.0, "verdict": "fn", "session_id": "s1",
            "rule_id": "my-custom-prefix", "category": "secret", "severity": "high",
            "hash": "aabb1122ccdd3344", "preview": "[REDACTED:12ch:hash=aabb1122]",
            "source": "<test>",
            "analysis": {"category": "secret", "confidence": 0.9,
                         "reason": "looks like an internal API key format",
                         "analyzed_ts": 1000.0},
        }
        log.write_text(json.dumps(entry) + "\n")

        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1",
               "LEAK_GUARD_RULES_DIR": str(rules_dir)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "promote"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        assert "my-custom-prefix" in r.stdout   # reported as promoted candidate
        # training log entry marked as promoted
        updated = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        assert updated[0].get("promoted") is True

    def test_promote_fp_writes_to_allowlist(self, tmp_path):
        """High-confidence FP entries are promoted as suppress_rules."""
        import subprocess
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "allowlist.toml").write_text("[suppress_rules]\n")
        (rules_dir / "pii.toml").write_text("")

        log = tmp_path / "training_log.jsonl"
        entry = {
            "ts": 1000.0, "verdict": "fp", "session_id": "s1",
            "rule_id": "high-entropy-base64", "category": "secret", "severity": "high",
            "hash": "ccdd3344eeff5566", "preview": "[REDACTED:10ch:hash=ccdd3344]",
            "source": "<test>",
            "analysis": {"category": "benign", "confidence": 0.85,
                         "reason": "internal session token, not a user secret",
                         "analyzed_ts": 1000.0},
        }
        log.write_text(json.dumps(entry) + "\n")

        env = {**os.environ, "LEAK_GUARD_STATE_DIR": str(tmp_path), "LEAK_GUARD_AUTHOR": "1",
               "LEAK_GUARD_RULES_DIR": str(rules_dir)}
        r = subprocess.run(
            [sys.executable, str(SCANNER), "train", "promote"],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, r.stderr
        allowlist = (rules_dir / "allowlist.toml").read_text()
        assert "high-entropy-base64" in allowlist
```

- [ ] **Step 2: Run to verify failure**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode::test_promote_fn_writes_to_rules tests/test_scanner.py::TestTrainingMode::test_promote_fp_writes_to_allowlist -v
```

- [ ] **Step 3: Implement `_train_promote()`**

```python
_PROMOTE_CONFIDENCE_THRESHOLD = 0.75
_RULES_DIR = Path(os.environ.get(
    "LEAK_GUARD_RULES_DIR",
    Path(__file__).parent.parent / "rules"
))


def _train_promote(dry_run: bool = False) -> int:
    """Promote high-confidence findings into repo rules.

    FN/unclear/confirm with confidence >= threshold → pii.toml candidate comment block.
    FP with benign analysis and confidence >= threshold → suppress_rules in allowlist.toml.
    Marks promoted entries in training_log.jsonl.
    """
    if not TRAINING_LOG.exists():
        print("train promote: no training_log.jsonl found", file=sys.stderr)
        return 1

    fn_candidates = []
    fp_candidates = []

    entries_raw = []
    for line in TRAINING_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            entries_raw.append(line)
            continue
        analysis = e.get("analysis") or {}
        conf = float(analysis.get("confidence", 0.0))
        cat = analysis.get("category", "")
        verdict = e.get("verdict", "pending")
        already_promoted = e.get("promoted", False)

        if already_promoted or conf < _PROMOTE_CONFIDENCE_THRESHOLD:
            entries_raw.append(json.dumps(e, default=str))
            continue

        if verdict == "fp" and cat == "benign":
            fp_candidates.append(e)
            e["promoted"] = True
        elif verdict in ("fn", "unclear", "confirm") and cat in ("secret", "pii"):
            fn_candidates.append(e)
            e["promoted"] = True

        entries_raw.append(json.dumps(e, default=str))

    if not fn_candidates and not fp_candidates:
        print("train promote: no high-confidence candidates found "
              f"(threshold={_PROMOTE_CONFIDENCE_THRESHOLD})")
        return 0

    # ── FN → pii.toml candidate block ────────────────────────────────────────
    if fn_candidates:
        pii_toml = _RULES_DIR / "pii.toml"
        block_lines = [f"\n# --- training-promoted candidates ({time.strftime('%Y-%m-%d')}) ---"]
        for e in fn_candidates:
            ana = e.get("analysis", {})
            block_lines += [
                f"# rule_id: {e['rule_id']}  confidence: {ana.get('confidence')}",
                f"# reason: {ana.get('reason','')}",
                f"# preview: {e['preview']}",
                f"# TODO: add regex pattern and uncomment [[pattern]] block below",
                f"# [[pattern]]",
                f"# rule_id = \"{e['rule_id']}\"",
                f"# regex = \"FILL_IN_PATTERN\"",
                f"# description = \"{ana.get('reason','')}\",
                f"# severity = \"{e['severity']}\"",
                "",
            ]
            print(f"  [FN] {e['rule_id']} (confidence={ana.get('confidence')}) → {pii_toml}")

        if not dry_run:
            with pii_toml.open("a", encoding="utf-8") as f:
                f.write("\n".join(block_lines))

    # ── FP → allowlist.toml suppress_rules ───────────────────────────────────
    if fp_candidates:
        allowlist_toml = _RULES_DIR / "allowlist.toml"
        fp_lines = [f"\n# training-promoted FP suppressions ({time.strftime('%Y-%m-%d')})"]
        fp_lines.append("[suppress_rules]")
        for e in fp_candidates:
            ana = e.get("analysis", {})
            fp_lines += [
                f"# confidence={ana.get('confidence')} reason={ana.get('reason','')}",
                f"{e['rule_id']} = true",
                "",
            ]
            print(f"  [FP] {e['rule_id']} (confidence={ana.get('confidence')}) → {allowlist_toml}")

        if not dry_run:
            with allowlist_toml.open("a", encoding="utf-8") as f:
                f.write("\n".join(fp_lines))

    if not dry_run:
        TRAINING_LOG.write_text("\n".join(entries_raw) + "\n", encoding="utf-8")
        print(f"\ntrain promote: {len(fn_candidates)} FN + {len(fp_candidates)} FP promoted.")
        print("Review the rule files, fill in TODO patterns, then commit and push to publish.")
        audit("train_promote", {"fn": len(fn_candidates), "fp": len(fp_candidates)})
    else:
        print(f"\ntrain promote --dry-run: {len(fn_candidates)} FN + {len(fp_candidates)} FP would be promoted.")

    return 0
```

Note: `_RULES_DIR` uses `LEAK_GUARD_RULES_DIR` env var so tests can point at a temp dir without touching the real rules.

- [ ] **Step 4: Run tests**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py::TestTrainingMode -v
```

- [ ] **Step 5: Run full suite**

```bash
/opt/homebrew/bin/python3 -m pytest tests/test_scanner.py -q
```
Expected: all passing.

- [ ] **Step 6: Commit**

```bash
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): add 'train promote' — auto-writes FN/FP into repo rules at confidence >= 0.75"
```

---

## Task 6: Author shell setup + selftest + install + push

- [ ] **Step 1: Set `LEAK_GUARD_AUTHOR=1` in author's shell**

```bash
echo 'export LEAK_GUARD_AUTHOR=1' >> ~/.zshrc
echo 'export LEAK_GUARD_AUTHOR=1' >> ~/.zprofile
source ~/.zshrc
```

- [ ] **Step 2: Add training check to `cmd_selftest()`**

After the proxy health block:

```python
    # Training mode (author-only)
    if _author_mode():
        try:
            _write_training_entry(
                [Finding("selftest-rule", "secret", "<selftest>", 0,
                         "[REDACTED:selftest:8ch:hash=00000000]",
                         raw_match="selftest-dummy")],
                session_id="selftest",
            )
            check("training log writable [author]", TRAINING_LOG.exists(), str(TRAINING_LOG))
        except Exception as exc:
            check("training log writable [author]", False, str(exc))
    else:
        check("training mode", True, "disabled (not author machine — expected)")
```

- [ ] **Step 3: Run selftest**

```bash
LEAK_GUARD_AUTHOR=1 /opt/homebrew/bin/python3 plugins/leak-guard/hooks/scanner.py selftest
```
Expected: `[PASS] training log writable [author]` in output.

- [ ] **Step 4: Sync cache and push**

```bash
/opt/homebrew/bin/python3 plugins/leak-guard/hooks/scanner.py install
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(training): selftest + author shell env setup"
git push origin main
```

---

## End-to-end workflow (author)

```bash
# 1. Scanner fires on a real prompt → training_log.jsonl auto-populated
# 2. Review what was captured
scanner.py train list --filter pending

# 3. Label obvious cases manually
scanner.py train verdict <hash> fp    # I know it's a false positive
scanner.py train verdict <hash> fn    # I know the scanner missed something

# 4. Ask Claude to analyze ambiguous ones
scanner.py train analyze
# Claude responds with ANALYSIS:<hash>:category=...:confidence=...:reason=...
# Then ingest:
scanner.py train ingest-analysis

# 5. Promote high-confidence findings into repo rules
scanner.py train promote --dry-run   # preview
scanner.py train promote             # write to rules/

# 6. Review, fill in TODO patterns, commit, publish
git diff plugins/leak-guard/rules/
git add plugins/leak-guard/rules/ && git commit -m "rules: promote training findings"
git push origin main
# → triggers CI → ready for marketplace publish
```

---

## Self-Review

- ✅ Author-only — gated by `LEAK_GUARD_AUTHOR=1`; other machines see zero training behavior
- ✅ Captures FP/FN/Unclear — `_write_training_entry()` writes all finding types
- ✅ LLM analysis — `train analyze` emits prompt; `train ingest-analysis` records response
- ✅ Confidence weighting — `0.0-1.0` float, threshold 0.75 for promotion
- ✅ Auto-promotes to shared ruleset — FN → `rules/pii.toml`, FP → `rules/allowlist.toml`
- ✅ Commit → publish path — promoted rules go into git, CI runs, marketplace publish
- ✅ No raw secrets stored — only `hash`, `preview` (redacted), `rule_id`
- ✅ `LEAK_GUARD_RULES_DIR` env var for test isolation
- ✅ Type consistency — `Finding.raw_match`, `.rule_id`, `.category`, `.severity`, `.preview`, `.source` match existing dataclass (scanner.py ~line 80)
---

## Addendum: Multi-project monitoring

Training captures findings from **all projects**, not just leak-guard itself. The training log is centralized in `~/Projects/leak-guard`.

### Shell setup (add to `~/.zshrc` alongside `LEAK_GUARD_AUTHOR=1`)

```bash
export LEAK_GUARD_STATE_DIR="$HOME/Projects/leak-guard/.training"
export LEAK_GUARD_RULES_DIR="$HOME/Projects/leak-guard/plugins/leak-guard/rules"
```

`LEAK_GUARD_STATE_DIR` redirects `training_log.jsonl` and `audit.log` to the leak-guard repo. Any project that triggers the scanner writes to this central location.

### Schema: `source` field carries the project

The `source` field already records the originating file/prompt path. For cross-project analysis it will include the working directory prefix:

```json
{"source": "/Users/rinehardramos/Projects/it-management-system/<user-prompt>", ...}
```

No schema change needed — `train list` and `train promote` already read `source`.

### `train list --project <name>` filter (add to Task 3)

In `_train_list()`, add an optional project filter:

```python
def _train_list(filter_verdict: str = "pending", project: str = "") -> int:
    ...
    shown = [e for e in entries
             if (filter_verdict == "all" or e.get("verdict") == filter_verdict)
             and (not project or project in e.get("source", ""))]
```

Add `--project` arg to the argparse `list` subcommand:

```python
    tl.add_argument("--project", default="", help="Filter by source project name")
```

Wire in `cmd_train()`:

```python
        "list": lambda: _train_list(args.filter, getattr(args, "project", "")),
```

### Publish path

When the author runs `train promote` and commits to `~/Projects/leak-guard`, the improved rules are bundled into the next plugin version and published to the Anthropic marketplace — all users get the improved detection without any training overhead on their machines.
