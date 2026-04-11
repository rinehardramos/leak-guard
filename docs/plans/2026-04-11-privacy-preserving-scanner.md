# Privacy-Preserving Scanner — Design Spec

> **Principle:** Sensitive data should never reach unintended recipients. Anthropic has no contractual relationship with the user's data subjects — their PII and secrets must not cross the trust boundary.

**Date:** 2026-04-11  
**Version:** 0.5.0  
**Status:** Design approved, pending implementation plan

---

## Problem

Today, leak-guard detects sensitive data but still sends the raw prompt to Anthropic (exit 0 + additionalContext). The "redaction" is advisory — Claude sees both the original value and the redaction note. This violates the trust-boundary principle: data should only flow to parties with a contractual relationship to the data subject.

Claude Code hooks fire locally **before** the API call. Exit 2 blocks the prompt — it never reaches Anthropic. This is our leverage.

## Architecture

### Trust Boundary Model

```
┌──────────────────────── LOCAL (user's machine) ────────────────────────┐
│                                                                        │
│  User prompt → Hook fires → Scanner detects findings                   │
│                                  │                                     │
│                         ┌────────┴────────┐                            │
│                      no findings      findings                         │
│                         │                 │                            │
│                    NER check?        Build highlighted                  │
│                   (symbolic)         preview + block                    │
│                         │            (exit 2)                          │
│                         │                 │                            │
│                    exit 0            User sees preview                  │
│                         │            ↵ Enter = redact                   │
│                         │            a = always allow                   │
│                         │                 │                            │
│                         │         ┌───────┴───────┐                    │
│                         │      redact          allow                   │
│                         │         │               │                    │
│                         │   Strip values     Add to allowlist          │
│                         │   Build symbolic   Pass original             │
│                         │   FP metadata                                │
│                         │         │               │                    │
└─────────────────────────┼─────────┼───────────────┼────────────────────┘
                          │         │               │
                   ── TRUST BOUNDARY ───────────────────────────
                          │         │               │
                          ▼         ▼               ▼
                    Clean prompt  Redacted      User-approved
                    (no PII)     prompt +       original
                                 symbolic       (explicit
                                 metadata       consent)
                          │         │               │
                          └─────────┴───────────────┘
                                    │
                             Anthropic API
```

**Guarantee:** Raw sensitive data NEVER crosses the trust boundary unless the user explicitly chooses "allow" (informed consent, value added to persistent allowlist).

---

## Component 1: Block-and-Preview (hook_user_prompt)

### Current behavior (v0.4.0)
- Findings detected → exit 0 + additionalContext with redacted prompt
- Raw prompt still sent to Anthropic
- Claude sees both original and redacted versions

### New behavior (v0.5.0)
- Findings detected → exit 2 (BLOCK — prompt never sent)
- User sees highlighted preview in terminal
- Single-key response: Enter = redact, `a` = allow

### Preview format

```
⚠ leak-guard: sensitive content detected — prompt blocked before sending.

Your message:
───────────────────────────────────────────────
Please update the payment config. The card is
 >>>4242 4242 4242 4242<<< and the API key is
 >>>sk-live-Kj8mP2qL7nR4xW5bYzD9cHf6<<<.
Also contact >>>john.smith@patient-records.org<<<
───────────────────────────────────────────────

Findings:
  1. [critical 0.95] credit-card — Luhn-validated card number
  2. [critical 0.95] stripe-secret-key — Vendor credential
  3. [low 0.90] email — Email address

Reply:
  ↵ Enter  — redact and send (any reply except 'a')
  a        — always allow these values
```

- `>>>value<<<` markers highlight flagged strings in the terminal
- Findings listed with severity, confidence score, and rule
- The preview is rendered via stderr — local only, never sent to Anthropic
- pending_action.json stores the prompt + redact targets (local, 600 perms, 5-min TTL)

### Turn 2 handling

```python
def _is_choice_reply(prompt: str) -> str | None:
    # Returns "redact" or "allow" or None
    if not PENDING_ACTION.exists():
        return None  # no active block — treat as normal prompt
    stripped = prompt.strip().lower()
    if stripped in ("a", "allow"):
        return "allow"
    if not stripped or stripped in ("r", "redact", ".", "y", "yes"):
        return "redact"
    # Long responses (>20 chars) are likely new prompts, not choices.
    # Delete the expired pending action and fall through to normal scan.
    if len(stripped) > 20:
        PENDING_ACTION.unlink(missing_ok=True)
        return None
    # Short non-keyword response with active pending → safe default
    return "redact"
```

**Safe default:** Any short response that isn't explicitly `a` or `allow` triggers redact. Long responses (>20 chars) are treated as new prompts — the pending action expires and normal scanning resumes. The dangerous action (sending raw data) requires deliberate `a` input.

### Redact flow

```python
# On "redact":
redacted_prompt = prompt
for f in findings:
    if f.raw_match:
        tag = _redaction_tag(f)  # e.g., [REDACTED:credit-card]
        redacted_prompt = redacted_prompt.replace(f.raw_match, tag)

# Inject redacted version + symbolic FP metadata via additionalContext
# Raw values stay local — only the redacted text crosses the boundary
emit_menu_prompt(redacted_prompt + symbolic_context)
```

### Allow flow

```python
# On "allow":
for target in redact_targets:
    # Append to ~/.claude/leak-guard/allowlist.toml
    _append_to_allowlist(target)
    # Log to FP profile for feedback loop
    _log_fp_decision(rule_id, context_keywords, position)

# Send original prompt — user gave informed consent
emit_allow_modified(original_prompt)
```

---

## Component 2: Semantic Redaction

Instead of generic `[REDACTED]`, use typed tags so Claude can reason about the task without seeing values.

### Tag mapping

| Source | Tag |
|---|---|
| PII rules (email, SSN, phone, etc.) | `[REDACTED:{rule_id}]` |
| Vendor secrets (github-pat, stripe, etc.) | `[REDACTED:credential]` |
| DB connection strings | `[REDACTED:connection-string]` |
| URL-embedded credentials | `[REDACTED:url-credential]` |
| NER name candidates | `[REDACTED:name]` |
| NER address candidates | `[REDACTED:address]` |
| NER medical/legal context | `[REDACTED:pii]` |
| Entropy/unknown | `[REDACTED:suspicious-value]` |

### Implementation

```python
def _redaction_tag(finding: Finding) -> str:
    """Return a semantic redaction tag based on finding type."""
    # NER candidates
    if finding.rule_id.startswith("ner-"):
        ner_type = finding.rule_id.split("-", 1)[1]  # ner-name → name
        return f"[REDACTED:{ner_type}]"
    # Vendor credentials → generic credential tag
    if finding.category == "secret":
        if finding.rule_id in ("db-connection-string",):
            return "[REDACTED:connection-string]"
        if finding.rule_id in ("url-embedded-credential",):
            return "[REDACTED:url-credential]"
        return "[REDACTED:credential]"
    # PII → use rule_id directly
    if finding.category == "pii":
        return f"[REDACTED:{finding.rule_id}]"
    return "[REDACTED:suspicious-value]"
```

### Claude's instruction (in additionalContext with redacted prompt)

```
The user's message contained sensitive content that was redacted before
reaching you. The redaction tags indicate what type of data was removed:
  [REDACTED:credit-card] — a payment card number
  [REDACTED:credential] — an API key or token
  [REDACTED:email] — an email address

Respond to the user's request using the redacted message. Where the
redacted values are needed for the task, advise the user to provide
anonymized or synthetic values instead. Do not attempt to guess or
reconstruct the redacted values.
```

---

## Component 3: Symbolic FP Reduction

When borderline findings (entropy, fuzzy) are detected, Claude receives a **symbolic fingerprint** — never the raw value.

### Fingerprint structure

```python
@dataclass
class SymbolicFingerprint:
    rule_id: str
    length: int
    entropy: float
    charset: str           # "base64url", "hex", "alphanumeric", "mixed"
    unique_ratio: float    # len(set(val)) / len(val)
    context_keywords: list[str]  # nearby keywords (lowercased)
    position: str          # "rhs_of_assignment", "standalone", "in_url", etc.
    has_vendor_prefix: bool
    adjacent_code: str     # surrounding code with value replaced by ___
```

### Building the fingerprint

```python
def _build_symbolic_fingerprint(finding: Finding, text: str) -> SymbolicFingerprint:
    val = finding.raw_match
    # Determine charset
    if all(c in "0123456789abcdefABCDEF" for c in val.replace("-", "")):
        charset = "hex"
    elif all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-" for c in val):
        charset = "base64url"
    else:
        charset = "mixed"

    # Extract surrounding code with value masked
    start = max(0, text.find(val) - 40)
    end = min(len(text), text.find(val) + len(val) + 40)
    window = text[start:end].replace(val, "___")

    # Find context keywords in window
    keywords = [kw for kw in _SECRET_CONTEXT_KEYWORDS if kw in window.lower()]

    # Determine position
    pre = text[max(0, text.find(val) - 5):text.find(val)]
    if re.search(r'[=:]\s*["\']?$', pre):
        position = "rhs_of_assignment"
    elif "://" in window:
        position = "in_url"
    else:
        position = "standalone"

    return SymbolicFingerprint(
        rule_id=finding.rule_id,
        length=len(val),
        entropy=_shannon_entropy(val),
        charset=charset,
        unique_ratio=len(set(val.lower())) / len(val),
        context_keywords=keywords,
        position=position,
        has_vendor_prefix=any(val.startswith(p) for p in _VENDOR_PREFIXES),
        adjacent_code=window,
    )
```

### Symbolic FP instruction (injected as additionalContext)

```
leak-guard: A borderline value was redacted. Symbolic profile:
  Rule: high-entropy-base64
  Length: 40 chars, entropy: 4.8 bits/char, charset: base64url
  Position: rhs_of_assignment
  Context keywords: "cache_key", "generate"
  Adjacent code: const cacheKey = generateHash(___)

If this profile suggests a computed/derived value rather than a
credential, inform the user it was likely a false positive and
they can re-send with 'a' to allowlist it.
```

Claude reasons about the **pattern** — length, entropy, surrounding code — without seeing the value itself.

---

## Component 4: Symbolic NER for Unstructured PII

### Stage 1: Local candidate extraction (stdlib regex)

```python
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

# Context keyword sets that elevate a candidate
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
```

### Candidate scoring

A candidate is elevated to a finding only when a context keyword appears within 100 chars:

```python
def _score_ner_candidate(match: re.Match, text: str, ner_type: str) -> float:
    """Return confidence score 0.0-1.0 for a NER candidate."""
    window = text[max(0, match.start() - 100):match.end() + 100].lower()
    score = 0.3  # base score for pattern match alone

    # Check all context keyword sets
    for domain, keywords in _NER_CONTEXT_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in window)
        if hits >= 2:
            score += 0.4  # strong contextual signal
        elif hits == 1:
            score += 0.2

    return min(score, 1.0)
```

A name candidate with no context keywords scores 0.3 — below the firing threshold (0.5). A name near "patient" and "diagnosed" scores 0.9 — strong signal.

### Stage 2: Symbolic classification (additionalContext)

For candidates that score >= 0.5, the hook:
1. Blocks the prompt (exit 2)
2. Replaces candidates with semantic tags: `[REDACTED:name]`, `[REDACTED:address]`
3. Sends symbolic summary to Claude:

```
leak-guard NER: unstructured PII candidates detected and redacted.

  1. [name] 2-word title-case sequence (confidence: 0.9)
     Context keywords: "patient", "diagnosed" (medical)

  2. [address] number + street pattern, 5 tokens (confidence: 0.7)
     Context keywords: "send", "mail"

These were redacted as [REDACTED:name] and [REDACTED:address].
The actual values never left the local machine.
```

### Interaction with regex findings

When a prompt has BOTH regex findings (SSN, vendor token) AND NER candidates (a name), the regex findings trigger the block. The NER scan runs on the SAME blocked prompt during redaction — both regex matches and NER candidates are replaced with semantic tags before the redacted version is sent. NER is not a separate pass that only fires when regex finds nothing; it augments the redaction of any blocked prompt.

The `not findings` guard for NER only applies to the **clean prompt path** (no block needed from regex) — in that case, NER candidates alone can trigger a block if they score >= 0.5.

### What NER does NOT catch (accepted gaps)

- Single-word names — too many false positives
- Non-English names without title-case convention
- Contextual PII without keyword markers
- Freeform text with no structural patterns

These gaps are acceptable. The regex layer already catches structured PII (SSN, CC, email). NER adds coverage for the highest-risk unstructured patterns. Perfect NER would require a model dependency (spaCy/transformers) which violates the stdlib-only constraint.

---

## Component 5: Confidence Scoring

Every finding gets a numeric confidence (0.0–1.0) displayed in the preview.

### Score assignment

| Source | Base confidence |
|---|---|
| Vendor-prefix regex (github-pat, stripe, etc.) | 0.95 |
| Structured PII regex (SSN, credit card Luhn-validated) | 0.90 |
| DB connection string / URL credential | 0.90 |
| Contextual PII (assigned-password, assigned-token) | 0.70 |
| NER candidate with context keywords | 0.50–0.90 (scored) |
| Entropy-only (high-entropy-base64/hex) | 0.50 |
| Fuzzy credential (PREFIX:value) | 0.50 |

### Implementation

```python
_CONFIDENCE_MAP: dict[str, float] = {
    # Vendor-specific — high confidence
    "aws-access-key-id": 0.95, "github-pat": 0.95, "stripe-secret-key": 0.95,
    # ... all vendor rules → 0.95
    
    # Structured PII — high confidence
    "us-ssn": 0.90, "credit-card": 0.90, "iban": 0.90,
    
    # Connection strings — high confidence
    "db-connection-string": 0.90, "url-embedded-credential": 0.90,
    
    # Contextual — medium confidence
    "assigned-password": 0.70, "assigned-token": 0.70,
    "assigned-api-key": 0.70, "assigned-secret": 0.70,
    
    # Heuristic — lower confidence
    "high-entropy-base64": 0.50, "high-entropy-hex": 0.50,
    "fuzzy-prefixed-credential": 0.50,
}

def _confidence(finding: Finding) -> float:
    return _CONFIDENCE_MAP.get(finding.rule_id, 0.60)
```

---

## Component 6: Feedback Loop

When users choose "allow", the decision is logged to build a local FP profile.

### Storage

File: `~/.claude/leak-guard/fp_profile.jsonl`  
Permissions: 0o600

```json
{"ts": 1744396800, "rule_id": "high-entropy-base64", "context_keywords": ["cache_key"], "position": "rhs_of_assignment", "charset": "base64url", "length": 40}
```

No raw values stored — only the symbolic profile of what was allowed.

### Usage in symbolic FP instruction

When a borderline finding matches a previously-allowed profile:

```
leak-guard: This value matches a pattern you previously allowed:
  Rule: high-entropy-base64, position: rhs_of_assignment,
  context: "cache_key" (allowed 3 times before)

This is likely a false positive based on your history.
```

This gives Claude additional signal AND builds user trust over time — the scanner learns from their decisions without storing any sensitive data.

---

## Component 7: PostToolUse NER

The same NER pipeline (Stage 1 + Stage 2) applies to tool output.

### Flow

```python
def hook_post_tool() -> int:
    # ... existing scan logic ...
    
    # If no regex findings, run NER on tool output
    if not findings and len(text) >= _NER_MIN_TEXT_LENGTH:
        ner_findings = _scan_ner_candidates(text, source=source)
        if ner_findings:
            # Block output — raw content never enters Claude's context
            redacted_output = text
            for f in ner_findings:
                redacted_output = redacted_output.replace(f.raw_match, _redaction_tag(f))
            symbolic = _build_ner_summary(ner_findings)
            emit_post_tool_block(
                f"leak-guard: unstructured PII detected in {tool} output. "
                f"Content redacted.\n{symbolic}"
            )
            return 0
    # ...
```

This catches the scenario where a developer `cat`s a patient record or a database dump — the NER layer blocks the output before Claude ingests it.

---

## Files Changed

| File | Change |
|---|---|
| `plugins/leak-guard/hooks/scanner.py` | Block-and-preview flow, semantic redaction, symbolic fingerprint builder, NER candidate extraction, confidence scoring, feedback loop, PostToolUse NER |
| `tests/test_scanner.py` | Tests for each component |
| `tests/fixtures/ground_truth.toml` | NER TP/FP fixtures |
| `README.md` | Updated architecture, privacy model, changelog |
| `.claude-plugin/marketplace.json` | Version bump to 0.5.0 |

---

## What's NOT in this design (and why)

- **Local NER model (spaCy/distilbert)** — violates stdlib-only constraint. The regex heuristic + symbolic Claude approach covers the highest-risk patterns without dependencies.
- **Prompt rewriting (updatedUserPrompt)** — not supported by Claude Code's UserPromptSubmit hook spec. Block + re-inject achieves the same result with one extra round-trip.
- **Partial redact/allow** — v1 is all-or-nothing per prompt. Granular per-finding control is a v2 feature. Users who need it can edit the allowlist directly.
- **Cross-prompt memory** — tracking secrets across conversation turns requires persistent state beyond the 5-minute pending_action TTL. Deferred to a future design.

---

## Success Criteria

1. **Privacy guarantee:** No raw sensitive value reaches Anthropic unless the user explicitly chooses "allow"
2. **Detection parity:** All existing regex/entropy/fuzzy detections continue working
3. **NER coverage:** Catches full names near medical/legal keywords, street addresses, dated records
4. **FP reduction:** Symbolic fingerprints give Claude enough signal to identify false positives
5. **UX:** Single-key response (Enter = safe default). Preview clearly shows what was caught.
6. **Performance:** Block-and-preview adds < 50ms to hook latency (no network calls)
7. **220+ existing tests pass** with no regressions
