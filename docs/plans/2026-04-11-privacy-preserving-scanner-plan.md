# Privacy-Preserving Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite leak-guard's enforcement model so raw sensitive values never cross the trust boundary to Anthropic unless the user explicitly allows it.

**Architecture:** Hook exits 2 on findings (blocks prompt before API call), shows a highlighted preview via stderr, user replies Enter (redact with semantic tags) or `a` (allow + persist to allowlist). Borderline findings include symbolic fingerprints for Claude's contextual judgment. Local NER catches unstructured PII (names near medical/legal keywords, addresses). A feedback loop learns from user allow decisions without storing raw values.

**Tech Stack:** Python 3.9+ stdlib only (scanner.py). No new dependencies.

**Design Spec:** `docs/plans/2026-04-11-privacy-preserving-scanner.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `plugins/leak-guard/hooks/scanner.py` | All new functions + modified hooks. Single-file scanner, stdlib only. |
| `tests/test_scanner.py` | All new test classes + updated existing tests. |
| `README.md` | Updated changelog + architecture description. |
| `.claude-plugin/marketplace.json` | Version bump 0.4.0 → 0.5.0. |

No new files created. All changes in existing files.

---

### Task 1: Confidence Scoring

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (insert after `_BORDERLINE_RULES` at line ~1522)
- Test: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after the `TestNerInstruction` class (~line 1183):

```python
class TestConfidenceScoring:
    """Component 5: Confidence scoring — every finding gets a 0.0-1.0 score."""

    def test_vendor_rule_high_confidence(self):
        f = sc.Finding("github-pat", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.95

    def test_structured_pii_confidence(self):
        f = sc.Finding("us-ssn", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.90

    def test_db_connection_confidence(self):
        f = sc.Finding("db-connection-string", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.90

    def test_assigned_password_medium_confidence(self):
        f = sc.Finding("assigned-password", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.70

    def test_entropy_low_confidence(self):
        f = sc.Finding("high-entropy-base64", "pii", "", 0, "[R]")
        assert sc._confidence(f) == 0.50

    def test_unknown_rule_default_confidence(self):
        f = sc.Finding("some-unknown-rule", "secret", "", 0, "[R]")
        assert sc._confidence(f) == 0.60
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestConfidenceScoring -v`
Expected: FAIL — `sc._confidence` does not exist.

- [ ] **Step 3: Write minimal implementation**

Insert in `scanner.py` after `_BORDERLINE_RULES` (line ~1522):

```python
# ── Component 5: Confidence scoring (0.0-1.0 per finding) ────────────────
_CONFIDENCE_MAP: dict[str, float] = {
    # Vendor-specific — high confidence
    "aws-access-key-id": 0.95, "aws-secret-access-key": 0.95,
    "github-pat": 0.95, "github-oauth": 0.95, "github-app-token": 0.95,
    "github-user-token": 0.95, "github-fine-grained-pat": 0.95,
    "anthropic-api-key": 0.95, "openai-api-key": 0.95,
    "stripe-secret-key": 0.95, "sendgrid-api-key": 0.95,
    "twilio-api-key": 0.95, "slack-token": 0.95, "slack-webhook": 0.95,
    "npm-token": 0.95, "pypi-token": 0.95, "google-api-key": 0.95,
    "gcp-api-key": 0.95, "private-key-header": 0.95, "private-key-encrypted": 0.95,
    "gitlab-pat": 0.95, "gitlab-pipeline-token": 0.95,
    "digitalocean-pat": 0.95, "digitalocean-oauth": 0.95,
    "heroku-api-key": 0.95, "discord-bot-token": 0.95,
    "mailgun-api-key": 0.95, "telegram-bot-token": 0.95,
    "hashicorp-vault-token": 0.95, "hashicorp-vault-batch": 0.95,
    "square-access-token": 0.95, "shopify-access-token": 0.95,
    "jwt-token": 0.90, "bearer-header": 0.90, "curl-auth-header": 0.90,
    # Structured PII — high confidence
    "us-ssn": 0.90, "credit-card": 0.90, "iban": 0.90,
    "uk-ni-number": 0.90, "ca-sin": 0.90, "au-tfn": 0.90,
    "in-aadhaar": 0.90, "mx-curp": 0.90, "de-personalausweis": 0.90,
    "email": 0.80, "us-phone": 0.80, "us-zip": 0.70, "ipv4-private": 0.60,
    # Connection strings — high confidence
    "db-connection-string": 0.90, "url-embedded-credential": 0.90,
    # Contextual — medium confidence
    "assigned-password": 0.70, "assigned-token": 0.70,
    "assigned-api-key": 0.70, "assigned-secret": 0.70,
    # Heuristic — lower confidence
    "high-entropy-base64": 0.50, "high-entropy-hex": 0.50,
    "fuzzy-prefixed-credential": 0.50,
    # NER candidates — medium confidence (actual score from _score_ner_candidate)
    "ner-name": 0.70, "ner-address": 0.70, "ner-dated-record": 0.70,
}


def _confidence(finding: Finding) -> float:
    """Return confidence score 0.0-1.0 for a finding."""
    return _CONFIDENCE_MAP.get(finding.rule_id, 0.60)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestConfidenceScoring -v`
Expected: all 6 PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): add confidence scoring map (Component 5)"
```

---

### Task 2: Semantic Redaction Tags

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (insert after `_confidence`)
- Test: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after `TestConfidenceScoring`:

```python
class TestSemanticRedaction:
    """Component 2: Semantic redaction — typed tags instead of generic [REDACTED]."""

    def test_pii_rule_uses_rule_id(self):
        f = sc.Finding("credit-card", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:credit-card]"

    def test_email_uses_rule_id(self):
        f = sc.Finding("email", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:email]"

    def test_vendor_secret_uses_credential(self):
        f = sc.Finding("github-pat", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:credential]"

    def test_db_connection_string_tag(self):
        f = sc.Finding("db-connection-string", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:connection-string]"

    def test_url_credential_tag(self):
        f = sc.Finding("url-embedded-credential", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:url-credential]"

    def test_ner_name_tag(self):
        f = sc.Finding("ner-name", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:name]"

    def test_ner_address_tag(self):
        f = sc.Finding("ner-address", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:address]"

    def test_entropy_uses_suspicious_value(self):
        f = sc.Finding("high-entropy-base64", "pii", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:suspicious-value]"

    def test_fuzzy_uses_suspicious_value(self):
        f = sc.Finding("fuzzy-prefixed-credential", "secret", "", 0, "[R]")
        assert sc._redaction_tag(f) == "[REDACTED:suspicious-value]"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestSemanticRedaction -v`
Expected: FAIL — `sc._redaction_tag` does not exist.

- [ ] **Step 3: Write minimal implementation**

Insert in `scanner.py` after `_confidence()`:

```python
# Rule IDs that map to specific non-generic redaction tags
_REDACTION_TAG_OVERRIDES: dict[str, str] = {
    "db-connection-string": "[REDACTED:connection-string]",
    "url-embedded-credential": "[REDACTED:url-credential]",
}

# Rules whose values are heuristic/entropy-based — use generic suspicious-value tag
_SUSPICIOUS_VALUE_RULES = _BORDERLINE_RULES  # high-entropy-*, fuzzy-prefixed-credential


def _redaction_tag(finding: Finding) -> str:
    """Return a semantic redaction tag based on finding type."""
    rid = finding.rule_id
    # NER candidates — extract type from rule_id prefix
    if rid.startswith("ner-"):
        ner_type = rid.split("-", 1)[1]  # ner-name → name
        return f"[REDACTED:{ner_type}]"
    # Specific overrides
    if rid in _REDACTION_TAG_OVERRIDES:
        return _REDACTION_TAG_OVERRIDES[rid]
    # Heuristic/entropy — suspicious value
    if rid in _SUSPICIOUS_VALUE_RULES:
        return "[REDACTED:suspicious-value]"
    # Vendor credentials → generic credential tag
    if finding.category == "secret":
        return "[REDACTED:credential]"
    # PII → use rule_id directly
    if finding.category == "pii":
        return f"[REDACTED:{rid}]"
    return "[REDACTED:suspicious-value]"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestSemanticRedaction -v`
Expected: all 9 PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): add semantic redaction tags (Component 2)"
```

---

### Task 3: NER Candidate Extraction

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (insert after `_redaction_tag`)
- Test: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after `TestSemanticRedaction`:

```python
class TestNerCandidates:
    """Component 4: Local NER — regex-based candidate extraction with context scoring."""

    def test_name_near_medical_keyword_detected(self):
        text = "The patient John Smith was diagnosed with pneumonia on 03/15/2025."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-name" for f in hits)

    def test_name_near_legal_keyword_detected(self):
        text = "The defendant Jane Doe filed a motion in court on Monday."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-name" for f in hits)

    def test_name_without_context_not_detected(self):
        """A name with no medical/legal/financial context should score below threshold."""
        text = "Please refactor the Hello World function in the codebase."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert not any(f.rule_id == "ner-name" for f in hits)

    def test_address_detected(self):
        text = "Send the package to 1234 Oak Street, Springfield."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-address" for f in hits)

    def test_dated_record_detected(self):
        text = "The patient was diagnosed with diabetes on 01/15/2024 at the clinic."
        hits = sc._scan_ner_candidates(text, source="<test>")
        assert any(f.rule_id == "ner-dated-record" for f in hits)

    def test_score_increases_with_multiple_keywords(self):
        """Two context keywords should score higher than one."""
        text_one = "The patient John Smith visited today."
        text_two = "The patient John Smith was diagnosed with pneumonia at the hospital."
        score_one = sc._score_ner_candidate_text(text_one, "name")
        score_two = sc._score_ner_candidate_text(text_two, "name")
        assert score_two > score_one

    def test_ner_finding_has_correct_category(self):
        text = "The patient John Smith was diagnosed with pneumonia."
        hits = sc._scan_ner_candidates(text, source="<test>")
        for h in hits:
            assert h.category == "pii"

    def test_ner_finding_raw_match_not_in_preview(self):
        text = "The patient John Smith was diagnosed with pneumonia."
        hits = sc._scan_ner_candidates(text, source="<test>")
        for h in hits:
            if h.raw_match:
                assert h.raw_match not in h.preview
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestNerCandidates -v`
Expected: FAIL — `sc._scan_ner_candidates` does not exist.

- [ ] **Step 3: Write minimal implementation**

Insert in `scanner.py` after `_redaction_tag()`:

```python
# ── Component 4: Symbolic NER — local regex + context scoring ─────────────

_NER_CANDIDATE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # Full name candidates (2-3 title-case words)
    ("ner-name",
     re.compile(r'\b[A-Z][a-z]{1,15}\s+[A-Z][a-z]{1,15}(?:\s+[A-Z][a-z]{1,15})?\b'),
     "name"),
    # Street address candidates (number + street type)
    ("ner-address",
     re.compile(r'\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+'
                r'(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|'
                r'Ln|Lane|Ct|Court|Way|Pl(?:ace)?|Pkwy)\b\.?', re.I),
     "address"),
    # Date near medical/legal keywords
    ("ner-dated-record",
     re.compile(r'(?i)(?:diagnosed|admitted|discharged|filed|sentenced|'
                r'prescribed|examined)\b.{0,30}\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'),
     "dated-record"),
]

_NER_CONTEXT_KEYWORDS: dict[str, frozenset[str]] = {
    "medical": frozenset({
        "patient", "diagnosed", "treatment", "hospital", "clinic",
        "medical", "prescription", "symptom", "condition", "surgery",
        "nurse", "doctor", "physician", "therapist",
    }),
    "legal": frozenset({
        "plaintiff", "defendant", "filed", "court", "case",
        "sentenced", "attorney", "counsel", "verdict", "hearing",
    }),
    "financial": frozenset({
        "account", "balance", "deposit", "withdrawal", "routing",
        "beneficiary", "wire", "transfer",
    }),
}

_NER_SCORE_THRESHOLD = 0.5


def _score_ner_candidate_text(text: str, ner_type: str) -> float:
    """Return confidence score 0.0-1.0 for a NER candidate based on context keywords.

    Exposed as a module function for testability (score_increases_with_multiple_keywords).
    """
    window = text.lower()
    score = 0.3  # base score for pattern match alone
    for domain, keywords in _NER_CONTEXT_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in window)
        if hits >= 2:
            score += 0.4
        elif hits == 1:
            score += 0.2
    return min(score, 1.0)


def _score_ner_candidate(match: re.Match, text: str, ner_type: str) -> float:
    """Return confidence score 0.0-1.0 for a NER candidate."""
    window = text[max(0, match.start() - 100):match.end() + 100]
    return _score_ner_candidate_text(window, ner_type)


def _scan_ner_candidates(text: str, source: str = "") -> list[Finding]:
    """Stage 1: Extract NER candidates via regex and score by context keywords.

    Only candidates scoring >= _NER_SCORE_THRESHOLD are returned as findings.
    """
    if not text or len(text) < 20:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for rule_id, pattern, ner_type in _NER_CANDIDATE_PATTERNS:
        for m in pattern.finditer(text):
            matched = m.group(0)
            if matched in seen:
                continue
            score = _score_ner_candidate(m, text, ner_type)
            if score < _NER_SCORE_THRESHOLD:
                continue
            seen.add(matched)
            upto = text[:m.start()]
            line_no = upto.count("\n") + 1
            severity = "high" if score >= 0.7 else "medium"
            findings.append(Finding(
                rule_id=rule_id,
                category="pii",
                description=f"NER {ner_type} candidate (confidence: {score:.1f})",
                line=line_no,
                preview=redact_preview(matched, ner_type),
                severity=severity,
                source=source,
                raw_match=matched,
            ))
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestNerCandidates -v`
Expected: all 8 PASS.

- [ ] **Step 5: Run full suite to check for regressions**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py -v`
Expected: all existing tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): add NER candidate extraction with context scoring (Component 4)"
```

---

### Task 4: Block-and-Preview Core

This is the central change: `hook_user_prompt()` now exits 2 on findings (blocking the prompt), renders a highlighted preview to stderr, and saves state for the turn-2 response.

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (lines ~1374-1645: `_write_pending_action`, `_is_choice_reply`, `_handle_choice`, `_build_menu_text`, `hook_user_prompt`)
- Modify: `tests/test_scanner.py` (update existing tests + add new tests)

- [ ] **Step 1: Write new tests for block-and-preview**

Add to `tests/test_scanner.py` after `TestNerCandidates`:

```python
class TestBlockAndPreview:
    """Component 1: Block-and-preview — exit 2 on findings, stderr preview, Enter/a choices."""

    def test_findings_exit_2(self, tmp_path):
        """Findings cause exit 2 (prompt blocked)."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, stderr = _run_hook_with_state(state, f"My key is {aws}")
        assert rc == 2, f"Expected exit 2 (block), got {rc}"

    def test_preview_in_stderr(self, tmp_path):
        """Preview with >>>value<<< markers appears in stderr."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, stderr = _run_hook_with_state(state, f"My key is {aws}")
        assert ">>>" in stderr and "<<<" in stderr
        assert "leak-guard" in stderr
        assert "Enter" in stderr or "redact" in stderr.lower()

    def test_pending_action_written(self, tmp_path):
        """pending_action.json is written with findings data."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        _run_hook_with_state(state, f"My key is {aws}")
        pending = state / "pending_action.json"
        assert pending.exists()
        data = json.loads(pending.read_text())
        assert "findings" in data
        assert "prompt" in data
        assert "expires_at" in data
        assert len(data["findings"]) > 0
        # Each finding has required fields
        f = data["findings"][0]
        assert "rule_id" in f
        assert "raw_match" in f
        assert "redaction_tag" in f
        assert "confidence" in f

    def test_clean_prompt_exits_0(self, tmp_path):
        """No findings → exit 0 (prompt passes through)."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, _ = _run_hook_with_state(state, "What is the weather?")
        assert rc == 0

    def test_redact_choice_sends_semantic_tags(self, tmp_path):
        """Turn 2 Enter/empty → redact with semantic tags via additionalContext."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        ssn = "123-45-6789"
        original = f"My SSN is {ssn}, is it safe?"
        _make_pending(state, original, [ssn],
                      findings=[{"rule_id": "us-ssn", "category": "pii",
                                 "severity": "high", "description": "SSN",
                                 "raw_match": ssn, "confidence": 0.90,
                                 "redaction_tag": "[REDACTED:us-ssn]"}])
        rc, out, _ = _run_hook_with_state(state, "")  # Enter = redact
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "[REDACTED:us-ssn]" in ctx
        assert ssn not in ctx

    def test_allow_choice_sends_original(self, tmp_path):
        """Turn 2 'a' → allow, sends original prompt."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        ssn = "123-45-6789"
        original = f"My SSN is {ssn}, is it safe?"
        _make_pending(state, original, [ssn],
                      findings=[{"rule_id": "us-ssn", "category": "pii",
                                 "severity": "high", "description": "SSN",
                                 "raw_match": ssn, "confidence": 0.90,
                                 "redaction_tag": "[REDACTED:us-ssn]"}])
        rc, out, _ = _run_hook_with_state(state, "a")  # allow
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert original in ctx

    def test_allow_once_still_bypasses(self, tmp_path):
        """[allow-once] prefix still bypasses all findings (exit 0)."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, _ = _run_hook_with_state(state, f"[allow-once] my key {aws}")
        assert rc == 0

    def test_long_reply_not_intercepted_as_choice(self, tmp_path):
        """Responses >20 chars with active pending are treated as new prompts."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        _make_pending(state, "original", ["val"],
                      findings=[{"rule_id": "test", "category": "pii",
                                 "severity": "high", "description": "",
                                 "raw_match": "val", "confidence": 0.90,
                                 "redaction_tag": "[REDACTED:test]"}])
        long_msg = "This is a completely new prompt about something else entirely"
        rc, out, _ = _run_hook_with_state(state, long_msg)
        # Should be treated as a new prompt (pending expired), not a choice
        assert rc == 0

    def test_ner_findings_included_in_block(self, tmp_path):
        """NER candidates augment regex findings in the block."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        text = "The patient John Smith was diagnosed with pneumonia. " + "My SSN is 123-45-6789."
        rc, out, stderr = _run_hook_with_state(state, text)
        assert rc == 2
        # Both SSN and name should appear in the preview
        assert "ner-name" in stderr or "John" in stderr
```

- [ ] **Step 2: Update `_make_pending` helper to support new format**

Update the `_make_pending` helper function (~line 651) to accept the new `findings` parameter:

```python
def _make_pending(state_dir: Path, prompt: str, redact_targets: list,
                  expires_delta: float = 300, findings: list | None = None) -> None:
    """Write a synthetic pending_action.json into state_dir."""
    if findings is None:
        findings = [{"rule_id": "test-rule", "category": "pii",
                     "severity": "high", "description": "test",
                     "raw_match": t, "confidence": 0.90,
                     "redaction_tag": "[REDACTED:test]"} for t in redact_targets]
    data = {
        "prompt": prompt,
        "findings": findings,
        "expires_at": time.time() + expires_delta,
    }
    p = state_dir / "pending_action.json"
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
```

- [ ] **Step 3: Run new tests to verify they fail**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestBlockAndPreview -v`
Expected: FAIL — behavior not yet implemented.

- [ ] **Step 4: Implement `_render_preview`**

Insert in `scanner.py` after `_scan_ner_candidates()`, before the existing `_action_picker`:

```python
def _render_preview(prompt: str, findings: list[Finding]) -> None:
    """Render highlighted preview to stderr. Local only — never sent to Anthropic."""
    highlighted = prompt
    for f in findings:
        if f.raw_match:
            highlighted = highlighted.replace(f.raw_match, f">>>{f.raw_match}<<<")
    lines = [
        "\n\u26a0 leak-guard: sensitive content detected \u2014 prompt blocked before sending.\n",
        "Your message:",
        "\u2500" * 47,
        highlighted,
        "\u2500" * 47,
        "\nFindings:",
    ]
    for i, f in enumerate(findings, 1):
        conf = _confidence(f)
        lines.append(f"  {i}. [{f.severity} {conf:.2f}] {f.rule_id} \u2014 {f.description}")
    lines.extend([
        "\nReply:",
        "  \u21b5 Enter  \u2014 redact and send (any reply except 'a')",
        "  a        \u2014 always allow these values",
    ])
    print("\n".join(lines), file=sys.stderr, flush=True)
```

- [ ] **Step 5: Implement `_build_redact_instruction`**

Insert after `_render_preview`:

```python
def _build_redact_instruction(redacted_prompt: str, findings: list[dict]) -> str:
    """Build the additionalContext instruction for the redact flow (Turn 2)."""
    tags_used = sorted(set(f["redaction_tag"] for f in findings))
    tag_list = "\n".join(f"  {tag}" for tag in tags_used)
    instruction = (
        "SYSTEM NOTE (leak-guard): The user's message contained sensitive content "
        "that was redacted before reaching you.\n\n"
        f"Redaction tags used:\n{tag_list}\n\n"
        f"Redacted message:\n{redacted_prompt}\n\n"
        "Respond to the user's request using the redacted message. Where the "
        "redacted values are needed for the task, advise the user to provide "
        "anonymized or synthetic values instead. Do not attempt to guess or "
        "reconstruct the redacted values."
    )
    return instruction
```

- [ ] **Step 6: Rewrite `_write_pending_action`**

Replace `_write_pending_action` (lines ~1374-1392) with:

```python
def _write_pending_action(prompt: str, findings: list[Finding]) -> None:
    """Write pending_action.json with mode 0o600.

    Stores enriched finding data for Turn 2 redact/allow handling.
    """
    try:
        ensure_state_dir()
        data = {
            "prompt": prompt,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "raw_match": f.raw_match,
                    "confidence": _confidence(f),
                    "redaction_tag": _redaction_tag(f),
                }
                for f in findings
            ],
            "expires_at": time.time() + _PENDING_TTL,
        }
        fd = os.open(str(PENDING_ACTION), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except Exception:
        pass
```

- [ ] **Step 7: Rewrite `_is_choice_reply`**

Replace `_is_choice_reply` (lines ~1412-1436) with:

```python
def _is_choice_reply(prompt: str) -> str | None:
    """Return 'redact' or 'allow' if prompt is a reply to the block-and-preview.

    Returns None if no pending_action.json exists or response is a new prompt.
    """
    try:
        if not PENDING_ACTION.exists():
            return None
    except Exception:
        return None
    stripped = prompt.strip().lower()
    # Explicit allow
    if stripped in ("a", "allow"):
        return "allow"
    # Enter (empty), or any short redact-like response
    if not stripped or stripped in ("r", "redact", ".", "y", "yes"):
        return "redact"
    # Long responses (>20 chars) are likely new prompts, not choices.
    if len(stripped) > 20:
        PENDING_ACTION.unlink(missing_ok=True)
        return None
    # Short non-keyword response with active pending → safe default
    return "redact"
```

- [ ] **Step 8: Rewrite `_handle_choice`**

Replace `_handle_choice` (lines ~1439-1482) with:

```python
def _handle_choice(choice: str, pending: dict) -> int:
    """Execute the user's choice from the block-and-preview.

    'redact': Replace raw values with semantic tags, send via additionalContext.
    'allow': Add values to allowlist, send original via additionalContext.
    """
    try:
        PENDING_ACTION.unlink(missing_ok=True)
    except Exception:
        pass

    original_prompt = pending.get("prompt", "")
    findings = pending.get("findings", [])

    if choice == "allow":
        for f in findings:
            raw = f.get("raw_match", "")
            if raw:
                _append_literal(raw, "user allowed via block-and-preview")
        emit_allow_modified(original_prompt)
        return 0

    # "redact" (default)
    redacted = original_prompt
    for f in findings:
        raw = f.get("raw_match", "")
        tag = f.get("redaction_tag", "[REDACTED]")
        if raw:
            redacted = redacted.replace(raw, tag)
    instruction = _build_redact_instruction(redacted, findings)
    emit_allow_modified(instruction)
    return 0
```

- [ ] **Step 9: Rewrite `hook_user_prompt`**

Replace `hook_user_prompt` (lines ~1557-1645) with:

```python
def hook_user_prompt() -> int:
    event = read_event()
    prompt = event.get("prompt", "") or ""
    session_id = event.get("session_id", "")

    # ── Turn 2: check if this is a reply to the block-and-preview ────────
    choice = _is_choice_reply(prompt)
    if choice is not None:
        pending = _read_pending_action()
        if pending is not None:
            return _handle_choice(choice, pending)

    allow_once = prompt.lstrip().startswith(_ALLOW_ONCE_PREFIX)

    allow = load_allowlist()
    findings = scan_all(text=prompt, source_label="<user-prompt>")

    # NER candidate extraction — augments regex findings
    ner_findings = _scan_ner_candidates(prompt, source="<user-prompt>")
    findings.extend(ner_findings)

    if not findings:
        # Clean prompt path — inject NER instruction for long text
        if len(prompt) >= _NER_MIN_TEXT_LENGTH:
            out = {"hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": _NER_INSTRUCTION,
            }}
            sys.stdout.write(json.dumps(out))
            sys.stdout.flush()
        return 0

    # [allow-once] prefix bypasses all findings.
    if allow_once:
        audit("allow_once_bypass", {})
        return 0

    # ── Block-and-preview: exit 2, render preview, save pending ──────────
    audit("block_user_prompt", {"count": len(findings)})
    _write_training_entry(findings, session_id=session_id)
    _write_pending_action(prompt, findings)
    _render_preview(prompt, findings)

    reason = "leak-guard: sensitive content detected — prompt blocked. Reply to redact or allow."
    out = {"decision": "block", "reason": reason}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 2
```

- [ ] **Step 10: Run new tests to verify they pass**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestBlockAndPreview -v`
Expected: all PASS.

- [ ] **Step 11: Update existing tests for new behavior**

Update `TestHookUserPrompt` — findings now cause exit 2:

```python
class TestHookUserPrompt:
    def _event(self, prompt: str) -> dict:
        return {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": "test"}

    def test_clean_prompt_no_output(self):
        rc, out, _ = run_hook("hook-user-prompt", self._event("what is the weather like?"))
        assert rc == 0
        if out:
            assert out.get("decision") != "block"

    def test_secret_in_prompt_blocked(self):
        """Secret prompt: hook exits 2 (blocked before sending)."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            self._event(f"My AWS key is {_AWS}, help me use it"),
        )
        assert rc == 2
        assert "leak-guard" in stderr
        assert ">>>" in stderr  # highlighted preview

    def test_pii_in_prompt_blocked(self):
        """PII prompt: hook exits 2 (blocked before sending)."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            self._event("My SSN is 123-45-6789, is it safe?"),
        )
        assert rc == 2
        assert "leak-guard" in stderr
```

Update `TestPromptInjectedPicker` for new choice format and pending structure:

```python
class TestPromptInjectedPicker:
    """Tests for the block-and-preview flow (Turn 1 + Turn 2)."""

    _CRED = "ScdsJCCKLSLKDKLCNLKCEINK2233as"

    def test_detection_blocks_prompt(self, tmp_path):
        """Detection: hook exits 2 (prompt blocked)."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, stderr = _run_hook_with_state(state, f"here is my new pass CSKC:{self._CRED}")
        assert rc == 2
        assert "leak-guard" in stderr

    def test_choice_allow_resends_original(self, tmp_path):
        """Turn 2 'a': exits 0 and sends original prompt."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = f"here is my pass CSKC:{self._CRED}"
        _make_pending(state, original, [self._CRED])
        rc, out, _ = _run_hook_with_state(state, "a")
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert original in ctx

    def test_choice_redact_uses_semantic_tags(self, tmp_path):
        """Turn 2 Enter: exits 0 and uses semantic redaction tags."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        original = f"here is my pass CSKC:{self._CRED}"
        _make_pending(state, original, [self._CRED])
        rc, out, _ = _run_hook_with_state(state, "")  # Enter = redact
        assert rc == 0
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        assert "[REDACTED:" in ctx
        assert self._CRED not in ctx

    def test_choice_expired_falls_through(self, tmp_path):
        """Expired pending file: choice reply falls through to normal scan."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        _make_pending(state, "some clean prompt", [], expires_delta=-1)
        rc, out, _ = _run_hook_with_state(state, "a")
        assert rc == 0

    def test_no_pending_no_intercept(self, tmp_path):
        """No pending file: single-letter prompt is not intercepted as choice."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, _ = _run_hook_with_state(state, "a")
        assert rc == 0

    def test_redaction_uses_semantic_tags(self, tmp_path):
        """Redacted prompt uses [REDACTED:type] tags."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        rc, out, stderr = _run_hook_with_state(state, f"here is my new pass CSKC:{self._CRED}")
        assert rc == 2
        assert self._CRED not in (out or {}).get("reason", "")
```

Update `TestFuzzyCredentials.test_hook_intercepts_original_prompt`:

```python
    def test_hook_blocks_original_prompt(self):
        """Hook blocks prompt (exit 2) when fuzzy credential detected."""
        rc, out, stderr = run_hook(
            "hook-user-prompt",
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": f"here is my new pass CSKC:{self._CRED}",
                "session_id": "test",
            },
        )
        assert rc == 2
        assert "leak-guard" in stderr
        assert self._CRED not in json.dumps(out or {})
```

Update `TestDummyValues.test_allow_once_bypasses_all_findings` — this still exits 0:

```python
    def test_allow_once_bypasses_all_findings(self):
        """[allow-once] prefix bypasses all findings — prompt sent as-is."""
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        rc, out, _ = run_hook(
            "hook-user-prompt",
            {"hook_event_name": "UserPromptSubmit",
             "prompt": f"[allow-once] export AWS_ACCESS_KEY_ID={aws}",
             "session_id": "test"},
        )
        assert rc == 0
```

Update `TestBorderlineConfidence.test_borderline_only_gets_judgment_note` — now exit 2:

```python
class TestBorderlineConfidence:
    def test_borderline_only_exits_2(self):
        """When all findings are borderline, hook still blocks (exit 2)."""
        prompt = "config_value=" + "Kj8" + "mP2" + "qL7" + "nR4" + "xW5" + "bYz" + "D9c" + "Hf6" + "eG3" + "tUo"
        rc, out, stderr = run_hook("hook-user-prompt", {"prompt": prompt})
        if rc == 2:
            assert "leak-guard" in stderr
```

- [ ] **Step 12: Run full test suite**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py -v`
Expected: all tests PASS (existing + new).

- [ ] **Step 13: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): block-and-preview enforcement model (Component 1)

Exit 2 blocks prompt before API call. Highlighted preview via stderr.
Enter = redact with semantic tags, a = allow + persist to allowlist.
Raw values never cross trust boundary without explicit user consent."
```

---

### Task 5: Symbolic FP Fingerprinting

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (insert after `_build_redact_instruction`)
- Modify: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after `TestBlockAndPreview`:

```python
class TestSymbolicFingerprint:
    """Component 3: Symbolic FP reduction — fingerprint without raw values."""

    def test_fingerprint_has_required_fields(self):
        f = sc.Finding("high-entropy-base64", "pii", "entropy hit", 1, "[R]",
                       raw_match="xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7")
        text = "const cacheKey = xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        fp = sc._build_symbolic_fingerprint(f, text)
        assert "rule_id" in fp
        assert "length" in fp
        assert "entropy" in fp
        assert "charset" in fp
        assert "context_keywords" in fp
        assert "position" in fp
        assert "adjacent_code" in fp

    def test_fingerprint_masks_raw_value(self):
        val = "xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        f = sc.Finding("high-entropy-base64", "pii", "", 1, "[R]", raw_match=val)
        text = f"secret = '{val}'"
        fp = sc._build_symbolic_fingerprint(f, text)
        assert val not in fp["adjacent_code"]
        assert "___" in fp["adjacent_code"]

    def test_fingerprint_detects_rhs_position(self):
        val = "xK9mP2qL7nR4xW5bYzD9cHf6eG3tUoIgAb7"
        f = sc.Finding("high-entropy-base64", "pii", "", 1, "[R]", raw_match=val)
        text = f'API_KEY = "{val}"'
        fp = sc._build_symbolic_fingerprint(f, text)
        assert fp["position"] == "rhs_of_assignment"

    def test_fingerprint_detects_hex_charset(self):
        val = "a3f8c1d9e7b2046fa3f8c1d9e7b2046f"
        f = sc.Finding("high-entropy-hex", "pii", "", 1, "[R]", raw_match=val)
        fp = sc._build_symbolic_fingerprint(f, f"hash = {val}")
        assert fp["charset"] == "hex"

    def test_symbolic_context_in_redact_instruction(self, tmp_path):
        """Borderline findings include symbolic fingerprint in redact instruction."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        val = "xK9" + "mP2" + "qL7" + "nR4" + "xW5" + "bYz" + "D9c" + "Hf6" + "eG3" + "tUo"
        original = f"secret = '{val}'"
        _make_pending(state, original, [val],
                      findings=[{"rule_id": "high-entropy-base64", "category": "pii",
                                 "severity": "high", "description": "entropy hit",
                                 "raw_match": val, "confidence": 0.50,
                                 "redaction_tag": "[REDACTED:suspicious-value]"}])
        rc, out, _ = _run_hook_with_state(state, "")  # redact
        ctx = (out or {}).get("hookSpecificOutput", {}).get("additionalContext", "")
        # Symbolic fingerprint metadata should be present
        assert "entropy" in ctx.lower() or "symbolic" in ctx.lower() or "profile" in ctx.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestSymbolicFingerprint -v`
Expected: FAIL — `sc._build_symbolic_fingerprint` does not exist.

- [ ] **Step 3: Implement `_build_symbolic_fingerprint`**

Insert in `scanner.py` after `_build_redact_instruction`:

```python
def _build_symbolic_fingerprint(finding: Finding, text: str) -> dict:
    """Build a symbolic fingerprint for a finding — never includes raw value."""
    val = finding.raw_match
    if not val:
        return {"rule_id": finding.rule_id, "length": 0, "entropy": 0.0,
                "charset": "unknown", "context_keywords": [], "position": "unknown",
                "adjacent_code": "", "has_vendor_prefix": False, "unique_ratio": 0.0}

    # Determine charset
    stripped = val.replace("-", "").replace("_", "")
    if stripped and all(c in "0123456789abcdefABCDEF" for c in stripped):
        charset = "hex"
    elif all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_~-" for c in val):
        charset = "base64url"
    else:
        charset = "mixed"

    # Extract surrounding code with value masked
    idx = text.find(val)
    if idx >= 0:
        start = max(0, idx - 40)
        end = min(len(text), idx + len(val) + 40)
        window = text[start:end].replace(val, "___")
    else:
        window = ""

    # Context keywords in window
    keywords = [kw for kw in _SECRET_CONTEXT_KEYWORDS if kw in window.lower()]

    # Determine position
    if idx >= 0:
        pre = text[max(0, idx - 5):idx]
        if re.search(r'[=:]\s*["\']?$', pre):
            position = "rhs_of_assignment"
        elif "://" in window:
            position = "in_url"
        else:
            position = "standalone"
    else:
        position = "unknown"

    return {
        "rule_id": finding.rule_id,
        "length": len(val),
        "entropy": round(_shannon_entropy(val), 2),
        "charset": charset,
        "unique_ratio": round(len(set(val.lower())) / len(val), 2) if val else 0.0,
        "context_keywords": keywords,
        "position": position,
        "has_vendor_prefix": any(val.startswith(p) for p in _VENDOR_PREFIXES),
        "adjacent_code": window,
    }
```

- [ ] **Step 4: Update `_handle_choice` redact path to include symbolic fingerprints**

In the `_handle_choice` function's redact branch, after building the instruction, add symbolic context for borderline findings:

```python
    # "redact" (default)
    redacted = original_prompt
    for f in findings:
        raw = f.get("raw_match", "")
        tag = f.get("redaction_tag", "[REDACTED]")
        if raw:
            redacted = redacted.replace(raw, tag)

    instruction = _build_redact_instruction(redacted, findings)

    # Add symbolic fingerprints for borderline findings
    borderline = [f for f in findings if f.get("rule_id") in _BORDERLINE_RULES]
    if borderline:
        fp_lines = ["\n\nleak-guard: Borderline values were redacted. Symbolic profiles:"]
        for f in borderline:
            raw = f.get("raw_match", "")
            if raw:
                dummy_finding = Finding(f["rule_id"], f.get("category", ""), "",
                                        0, "", raw_match=raw)
                fp = _build_symbolic_fingerprint(dummy_finding, original_prompt)
                fp_lines.append(
                    f"  Rule: {fp['rule_id']}\n"
                    f"  Length: {fp['length']} chars, entropy: {fp['entropy']} bits/char, "
                    f"charset: {fp['charset']}\n"
                    f"  Position: {fp['position']}\n"
                    f"  Context keywords: {', '.join(fp['context_keywords']) or 'none'}\n"
                    f"  Adjacent code: {fp['adjacent_code']}"
                )
        fp_lines.append(
            "\nIf these profiles suggest computed/derived values rather than "
            "credentials, inform the user they were likely false positives and "
            "they can re-send with 'a' to allowlist them."
        )
        instruction += "\n".join(fp_lines)

    emit_allow_modified(instruction)
    return 0
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestSymbolicFingerprint -v`
Expected: all 5 PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): symbolic FP fingerprinting for borderline findings (Component 3)"
```

---

### Task 6: Feedback Loop

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (add `FP_PROFILE` path, `_log_fp_decision`, `_match_fp_profile`)
- Modify: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after `TestSymbolicFingerprint`:

```python
class TestFeedbackLoop:
    """Component 6: FP profile — learn from user allow decisions without raw values."""

    def test_fp_decision_logged_on_allow(self, tmp_path):
        """Allow choice logs symbolic FP profile to fp_profile.jsonl."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        val = "xK9" + "mP2" + "qL7" + "nR4" + "xW5" + "bYz" + "D9c" + "Hf6" + "eG3" + "tUo"
        original = f"cache_key = {val}"
        _make_pending(state, original, [val],
                      findings=[{"rule_id": "high-entropy-base64", "category": "pii",
                                 "severity": "high", "description": "entropy",
                                 "raw_match": val, "confidence": 0.50,
                                 "redaction_tag": "[REDACTED:suspicious-value]"}])
        rc, out, _ = _run_hook_with_state(state, "a")  # allow
        fp_log = state / "fp_profile.jsonl"
        assert fp_log.exists()
        entries = [json.loads(l) for l in fp_log.read_text().splitlines() if l.strip()]
        assert len(entries) >= 1
        e = entries[0]
        assert e["rule_id"] == "high-entropy-base64"
        assert "length" in e
        assert "raw_match" not in e  # raw value never stored

    def test_fp_profile_no_raw_values(self, tmp_path):
        """FP profile must never contain raw matched values."""
        state = tmp_path / "state"
        state.mkdir(mode=0o700)
        val = "xK9" + "mP2" + "qL7" + "nR4" + "xW5" + "bYz" + "D9c" + "Hf6" + "eG3" + "tUo"
        original = f"token = {val}"
        _make_pending(state, original, [val],
                      findings=[{"rule_id": "high-entropy-base64", "category": "pii",
                                 "severity": "high", "description": "entropy",
                                 "raw_match": val, "confidence": 0.50,
                                 "redaction_tag": "[REDACTED:suspicious-value]"}])
        _run_hook_with_state(state, "a")
        content = (state / "fp_profile.jsonl").read_text()
        assert val not in content

    def test_match_fp_profile(self):
        """_match_fp_profile returns previous allow count when profile matches."""
        # Direct unit test of the matching function
        profile = {"rule_id": "high-entropy-base64", "charset": "base64url",
                    "position": "rhs_of_assignment", "length": 40}
        history = [
            {"rule_id": "high-entropy-base64", "charset": "base64url",
             "position": "rhs_of_assignment", "length": 38},
            {"rule_id": "high-entropy-base64", "charset": "base64url",
             "position": "rhs_of_assignment", "length": 42},
            {"rule_id": "email", "charset": "mixed",
             "position": "standalone", "length": 20},
        ]
        count = sc._match_fp_profile(profile, history)
        assert count == 2  # two matching entries
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestFeedbackLoop -v`
Expected: FAIL — functions don't exist.

- [ ] **Step 3: Implement feedback loop**

Add to `scanner.py` near the top constants section (after `VERIFIER_FEEDBACK`):

```python
FP_PROFILE = STATE_DIR / "fp_profile.jsonl"
```

Add after `_build_symbolic_fingerprint`:

```python
def _log_fp_decision(finding_data: dict, prompt: str) -> None:
    """Log a symbolic FP profile when the user chooses 'allow'. No raw values stored."""
    try:
        ensure_state_dir()
        raw = finding_data.get("raw_match", "")
        dummy = Finding(finding_data["rule_id"], finding_data.get("category", ""),
                        "", 0, "", raw_match=raw)
        fp = _build_symbolic_fingerprint(dummy, prompt)
        # Strip adjacent_code and add timestamp — never store raw values
        entry = {
            "ts": time.time(),
            "rule_id": fp["rule_id"],
            "length": fp["length"],
            "entropy": fp["entropy"],
            "charset": fp["charset"],
            "position": fp["position"],
            "context_keywords": fp["context_keywords"],
            "has_vendor_prefix": fp["has_vendor_prefix"],
        }
        with FP_PROFILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _match_fp_profile(profile: dict, history: list[dict]) -> int:
    """Return count of previous allow decisions matching this profile."""
    count = 0
    for h in history:
        if (h.get("rule_id") == profile.get("rule_id")
                and h.get("charset") == profile.get("charset")
                and h.get("position") == profile.get("position")):
            count += 1
    return count
```

- [ ] **Step 4: Wire `_log_fp_decision` into `_handle_choice` allow path**

In `_handle_choice`, update the allow branch:

```python
    if choice == "allow":
        original_prompt = pending.get("prompt", "")
        for f in findings:
            raw = f.get("raw_match", "")
            if raw:
                _append_literal(raw, "user allowed via block-and-preview")
                _log_fp_decision(f, original_prompt)
        emit_allow_modified(original_prompt)
        return 0
```

- [ ] **Step 4b: Wire `_match_fp_profile` into symbolic context (redact path)**

In `_handle_choice`'s redact branch, after building symbolic fingerprints for borderline findings, load the FP profile and add match info:

```python
    # Load FP history for profile matching
    fp_history = []
    if FP_PROFILE.exists():
        try:
            fp_history = [json.loads(l) for l in
                          FP_PROFILE.read_text(encoding="utf-8").splitlines()
                          if l.strip()]
        except Exception:
            pass

    if borderline:
        fp_lines = ["\n\nleak-guard: Borderline values were redacted. Symbolic profiles:"]
        for f in borderline:
            raw = f.get("raw_match", "")
            if raw:
                dummy_finding = Finding(f["rule_id"], f.get("category", ""),
                                        "", 0, "", raw_match=raw)
                fp = _build_symbolic_fingerprint(dummy_finding, original_prompt)
                profile = {"rule_id": fp["rule_id"], "charset": fp["charset"],
                           "position": fp["position"], "length": fp["length"]}
                match_count = _match_fp_profile(profile, fp_history)
                fp_lines.append(
                    f"  Rule: {fp['rule_id']}\n"
                    f"  Length: {fp['length']} chars, entropy: {fp['entropy']} bits/char, "
                    f"charset: {fp['charset']}\n"
                    f"  Position: {fp['position']}\n"
                    f"  Context keywords: {', '.join(fp['context_keywords']) or 'none'}\n"
                    f"  Adjacent code: {fp['adjacent_code']}"
                )
                if match_count > 0:
                    fp_lines.append(
                        f"  Previously allowed: {match_count} time(s) — likely false positive."
                    )
        fp_lines.append(
            "\nIf these profiles suggest computed/derived values rather than "
            "credentials, inform the user they were likely false positives and "
            "they can re-send with 'a' to allowlist them."
        )
        instruction += "\n".join(fp_lines)
```

This replaces the corresponding code block in Task 5 Step 4 — Task 6 adds the profile-matching enhancement on top.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestFeedbackLoop -v`
Expected: all 3 PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): FP feedback loop with symbolic profiles (Component 6)"
```

---

### Task 7: PostToolUse NER

**Files:**
- Modify: `plugins/leak-guard/hooks/scanner.py` (modify `hook_post_tool` at line ~1712)
- Modify: `tests/test_scanner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_scanner.py` after `TestFeedbackLoop`:

```python
class TestPostToolNer:
    """Component 7: PostToolUse NER — catch unstructured PII in tool output."""

    def test_name_in_read_output_blocked(self):
        """NER-detected name in Read output triggers block."""
        text = (
            "Patient records:\n"
            "The patient John Smith was diagnosed with pneumonia.\n"
            "Treatment plan was discussed with the physician.\n"
        ) + "Additional notes. " * 15  # pad to exceed NER min length
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/patient_notes.txt"},
            "tool_response": {"content": text},
            "session_id": "test",
        }
        rc, out, stderr = run_hook("hook-post-tool", event)
        assert rc == 0  # PostToolUse always exits 0
        if out and out.get("decision") == "block":
            reason = out.get("reason", "")
            assert "ner" in reason.lower() or "PII" in reason or "REDACTED" in reason

    def test_short_output_no_ner(self):
        """Short tool output should not trigger NER scan."""
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/short.txt"},
            "tool_response": {"content": "Hello World"},
            "session_id": "test",
        }
        rc, out, _ = run_hook("hook-post-tool", event)
        assert rc == 0
        assert out is None or out.get("decision") != "block"

    def test_output_with_regex_findings_no_ner(self):
        """When regex finds secrets, NER is not needed (already blocked)."""
        aws = "AKIA" + "Y3FDSNDKFK" + "SIDJSW"
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/creds.txt"},
            "tool_response": {"content": f"AWS_KEY={aws}\n"},
            "session_id": "test",
        }
        rc, out, _ = run_hook("hook-post-tool", event)
        assert rc == 0
        assert out is not None
        assert out.get("decision") == "block"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestPostToolNer -v`
Expected: FAIL (NER not wired into post-tool yet — name-in-read test may not trigger block).

- [ ] **Step 3: Modify `hook_post_tool` to include NER fallback**

In `hook_post_tool` (line ~1712), add NER scanning after the existing PII block:

```python
def hook_post_tool() -> int:
    event = read_event()
    tool = event.get("tool_name", "")
    if tool not in POST_TOOL_SCAN_OUTPUT:
        return 0
    response = event.get("tool_response", {})
    text = _extract_response_text(tool, response)
    if not text:
        return 0
    tool_input = event.get("tool_input", {}) or {}
    source = _extract_response_source(tool, tool_input)
    allow = load_allowlist()
    silent = allow.silent_blocks
    if tool == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path and path_allowlisted(file_path, allow):
            return 0
    if tool == "Bash" and allow.bash_globs:
        cmd = tool_input.get("command", "") or source
        if any(fnmatch.fnmatch(cmd, g) for g in allow.bash_globs):
            return 0
    findings = scan_all(text=text, source_label=source)
    if not findings:
        # NER fallback — catch unstructured PII in tool output
        if len(text) >= _NER_MIN_TEXT_LENGTH:
            ner_findings = _scan_ner_candidates(text, source=source)
            if ner_findings:
                redacted = text
                for f in ner_findings:
                    if f.raw_match:
                        redacted = redacted.replace(f.raw_match, _redaction_tag(f))
                ner_summary = "\n".join(
                    f"  {f.rule_id} ({f.severity}) \u2014 {f.preview}"
                    for f in ner_findings
                )
                emit_post_tool_block(
                    f"leak-guard: unstructured PII detected in {tool} output. "
                    f"Content redacted.\n{ner_summary}",
                    silent=silent,
                )
                return 0
        return 0
    secrets, pii = classify(findings)
    if secrets:
        audit("block_post_tool_secret", {"tool": tool, "source": source, "count": len(secrets)})
        notice = _maybe_emit_verifier_notice(secrets[0].rule_id, secrets[0].category)
        reason = (
            f"leak-guard BLOCKED {tool} output from {source}: secrets present. "
            f"Content withheld from context.\n{format_summary(secrets)}\n"
            "Action: remove secrets from the source, add the path to allowlist, or scan explicitly with /scan-leaks."
        )
        if notice:
            reason += "\n" + notice
        emit_post_tool_block(reason, silent=silent)
        return 0
    if pii:
        audit("block_post_tool_pii", {"tool": tool, "source": source, "count": len(pii)})
        emit_post_tool_block(
            f"leak-guard BLOCKED {tool} output from {source}: PII present. "
            f"Content withheld.\n{format_summary(pii)}\n"
            "Action: rephrase the query, or add the path/rule to ~/.claude/leak-guard/allowlist.toml.",
            silent=silent,
        )
        return 0
    return 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py::TestPostToolNer -v`
Expected: all 3 PASS.

- [ ] **Step 5: Run full test suite**

Run: `cd /Users/rinehardramos/Projects/leak-guard && python3 -m pytest tests/test_scanner.py -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py tests/test_scanner.py
git commit -m "feat(scanner): PostToolUse NER fallback for unstructured PII (Component 7)"
```

---

### Task 8: Version Bump, Docs, and Integration

**Files:**
- Modify: `README.md`
- Modify: `.claude-plugin/marketplace.json`
- Modify: `plugins/leak-guard/hooks/scanner.py` (version strings)

- [ ] **Step 1: Update version in scanner.py**

Find the `_SELF_SUPPRESSION_INSTRUCTION` string and `hook_session_start` that reference version 0.4.0, update to 0.5.0.

- [ ] **Step 2: Update `.claude-plugin/marketplace.json`**

Change `"version": "0.4.0"` to `"version": "0.5.0"`.

- [ ] **Step 3: Update `README.md`**

Add v0.5.0 changelog entry:

```markdown
### v0.5.0 (2026-04-11)
- **Privacy guarantee:** Raw sensitive values never reach Anthropic unless user explicitly allows
- **Block-and-preview:** Hook exits 2 on findings, shows highlighted preview, Enter = redact / a = allow
- **Semantic redaction:** Typed `[REDACTED:{type}]` tags so Claude can reason about the task
- **Symbolic FP reduction:** Borderline findings include metadata (entropy, charset, position) for Claude's judgment — raw value never sent
- **Local NER:** Regex-based name/address/dated-record extraction with context keyword scoring
- **Confidence scoring:** Every finding gets a 0.0–1.0 confidence displayed in preview
- **Feedback loop:** User allow decisions build local FP profile (symbolic only, no raw values)
- **PostToolUse NER:** Tool output scanned for unstructured PII (names near medical/legal keywords)
```

Update the version badge from 0.3.0 to 0.5.0.

Update the "How it works" diagram to reflect exit 2 flow.

- [ ] **Step 4: Run full test suite + selftest**

Run:
```bash
cd /Users/rinehardramos/Projects/leak-guard
python3 -m pytest tests/test_scanner.py -v
python3 plugins/leak-guard/hooks/scanner.py selftest
```
Expected: all tests PASS, all selftest checks OK.

- [ ] **Step 5: Commit**

```bash
cd /Users/rinehardramos/Projects/leak-guard
git add plugins/leak-guard/hooks/scanner.py README.md .claude-plugin/marketplace.json
git commit -m "chore: bump version to 0.5.0, update changelog and docs"
```

---

## Summary

| Task | Component | Key Changes |
|---|---|---|
| 1 | Confidence Scoring | `_CONFIDENCE_MAP`, `_confidence()` |
| 2 | Semantic Redaction | `_redaction_tag()` — typed `[REDACTED:{type}]` tags |
| 3 | NER Extraction | `_scan_ner_candidates()`, `_score_ner_candidate()`, context keyword scoring |
| 4 | Block-and-Preview | Exit 2 flow, `>>><<<` preview, Enter/a choices, updated existing tests |
| 5 | Symbolic FP | `_build_symbolic_fingerprint()`, masked adjacent code in redact context |
| 6 | Feedback Loop | `fp_profile.jsonl`, `_log_fp_decision()`, `_match_fp_profile()` |
| 7 | PostToolUse NER | NER fallback in `hook_post_tool()` |
| 8 | Version + Docs | 0.5.0 bump, README changelog, selftest verification |

**Testing strategy:** TDD throughout — write failing test, implement, verify pass. Each task commits independently. Full suite run at Task 7 and Task 8 checkpoints.

**Risk mitigation:** Tasks 1-3 are purely additive (no existing behavior changes). Task 4 is the highest-risk change (modifies core hook flow). Tasks 5-7 build on top. If Task 4 causes regressions, the independent commits allow easy revert.
