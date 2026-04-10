#!/usr/bin/env python3
"""
Adversarial test suite for leak-guard.

Generates 100 prompts crafted to probe the scanner's detection and
evasion-resistance, runs each through the hook-user-prompt subcommand,
and reports a detailed results table.

Usage:
    python tests/adversarial_suite.py

All secrets are constructed at runtime via _j() so that this source file
itself does not contain literal secret patterns.
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

SCANNER = Path(__file__).resolve().parent.parent / "plugins" / "leak-guard" / "hooks" / "scanner.py"


# ──────────────────────────────────────────────────────────────────────────────
# Runtime secret construction — splits patterns so the scanner never sees
# a literal match in this source file.
# ──────────────────────────────────────────────────────────────────────────────

def _j(*parts: str) -> str:
    return "".join(parts)


AWS_KEY    = _j("AKIA", "Y3FDSNDKFK", "SIDJSW")
GH_PAT     = _j("ghp_", "R8mN2kLpQ7vX", "dYeZwBtA5cJfH", "sUoIgPn3m1")
STRIPE_KEY = _j("sk_live_", "aBcDeFgH", "iJkLmNoPqRsTuVwX")
SLACK_TOK  = _j("xoxb-", "123456789012", "-1234567890123", "-abcdefghijk")
JWT        = _j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiJ1c2VyMTIzIn0",
                ".", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

SSN        = "-".join(["123", "45", "6789"])
CC         = " ".join(["4532", "0151", "1283", "0366"])
PHONE      = _j("(555) ", "867-5309")
EMAIL      = _j("alice", "@corp-internal.io")

CSKC       = _j("CSKC:", "ScdsJCCKLSLKDKLCNLKCEINK2233as")
MYAPP      = _j("MYAPP:", "xK9ScdsJCCKLSLKDKLC", "NLKCE12as")

HE1        = _j("xK9mLpQ7vXdYe", "ZwBtA5cJfHsUoIgPn3m")
HE2        = _j("mN2kLpQ7vXdYe", "ZwBtA5cJfHsUoIgPn3m1R8")
HE3        = _j("R8mN2kLpQ7vX", "dYeZwBtA5cJfHsUoIgPn")


# ──────────────────────────────────────────────────────────────────────────────
# Test corpus — (label, prompt, expect_blocked)
# expect_blocked: True = should block, False = should pass, None = uncertain
# ──────────────────────────────────────────────────────────────────────────────

TESTS: list[tuple[str, str, bool | None]] = [

    # ── A: Standard known secrets in conversation ────────────────────────────

    ("A01 AWS key in plain request",
     f"Please store my AWS key: {AWS_KEY}",
     True),

    ("A02 GitHub PAT in push request",
     f"Push to the repo using this token: {GH_PAT}",
     True),

    ("A03 Stripe key in code snippet",
     f"Here is my Stripe key: {STRIPE_KEY}",
     True),

    ("A04 Slack token in notification request",
     f"Send a Slack notification with token {SLACK_TOK}",
     True),

    ("A05 JWT to decode",
     f"Can you decode this JWT for me? {JWT}",
     True),

    ("A06 Bearer token in curl command",
     f"curl -H 'Authorization: Bearer {GH_PAT}' https://api.github.com/user",
     True),

    ("A07 AWS key in shell export",
     f"export AWS_ACCESS_KEY_ID={AWS_KEY}",
     True),

    ("A08 Stripe key in Python assignment",
     f"stripe.api_key = '{STRIPE_KEY}'",
     True),

    ("A09 GitHub token in git remote URL",
     f"git remote set-url origin https://{GH_PAT}@github.com/org/repo.git",
     True),

    ("A10 API key in query string param",
     f"https://api.example.com/data?api_key={AWS_KEY}&format=json",
     True),


    # ── B: PII in conversation ───────────────────────────────────────────────

    ("B01 SSN plain",
     f"My Social Security number is {SSN}.",
     True),

    ("B02 Credit card in payment request",
     f"Charge this card: {CC}, exp 12/26, CVV 123.",
     True),

    ("B03 Email address alone",
     f"Send an email to {EMAIL}.",
     False),

    ("B04 Phone in customer record",
     f"Customer phone: {PHONE}",
     None),

    ("B05 SSN + full name",
     f"Name: John Doe, SSN: {SSN}",
     True),

    ("B06 SSN in JSON blob",
     f'{{"user": "jdoe", "ssn": "{SSN}", "active": true}}',
     True),

    ("B07 Credit card in YAML",
     f"payment:\n  card: '{CC}'\n  exp: '12/26'",
     True),

    ("B08 SSN in CSV row",
     f"John,Doe,{SSN},active",
     True),

    ("B09 Email + password context",
     f"Login: {EMAIL} / password = Hunter2!",
     None),

    ("B10 SSN in SQL WHERE clause",
     f"SELECT * FROM users WHERE ssn = '{SSN}';",
     True),


    # ── C: Secrets embedded in code ─────────────────────────────────────────

    ("C01 AWS key in Python dict",
     f"config = {{'aws_key': '{AWS_KEY}', 'region': 'us-east-1'}}",
     True),

    ("C02 Stripe in JavaScript Stripe() call",
     f"const stripe = Stripe('{STRIPE_KEY}');",
     True),

    ("C03 GitHub token in YAML CI env",
     f"env:\n  GH_TOKEN: {GH_PAT}\n  NODE_ENV: production",
     True),

    ("C04 .env file with AWS key + secret",
     f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     True),

    ("C05 JWT in localStorage.setItem",
     f"localStorage.setItem('token', '{JWT}');",
     True),

    ("C06 Slack token in shell var assignment",
     f"SLACK_TOKEN={SLACK_TOK}",
     True),

    ("C07 Stripe in Ruby assignment",
     f"Stripe.api_key = '{STRIPE_KEY}'",
     True),

    ("C08 GitHub token in fetch() Authorization header",
     f"fetch(url, {{headers: {{Authorization: 'Bearer {GH_PAT}'}}}});",
     True),

    ("C09 PEM private key header",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4",
     True),

    ("C10 Stripe key in docker-compose environment block",
     f"environment:\n  - STRIPE_KEY={STRIPE_KEY}\n  - PORT=8080",
     True),


    # ── D: Conversational evasion framing ───────────────────────────────────

    ("D01 I already rotated this + AWS key",
     f"Don't worry, I already rotated this key: {AWS_KEY}",
     True),

    ("D02 For example a key looks like + AWS key",
     f"For example, an AWS key looks like: {AWS_KEY}",
     True),

    ("D03 This expired Stripe key was + key",
     f"This expired Stripe key was: {STRIPE_KEY}",
     True),

    ("D04 Use a fake key like X in your tests + AWS key",
     f"Use a fake key like {AWS_KEY} in your tests.",
     True),

    ("D05 Why does my code fail? token = ... + GH_PAT",
     f"Why does my code fail? token = '{GH_PAT}'",
     True),

    ("D06 Debug this env: AWS_KEY=... + key",
     f"Debug this env: AWS_ACCESS_KEY_ID={AWS_KEY}",
     True),

    ("D07 Does this look like a valid key? + AWS key",
     f"Does this look like a valid AWS key? {AWS_KEY}",
     True),

    ("D08 Found this in logs, should I worry? token=... + Slack",
     f"Found this in logs, should I worry? token={SLACK_TOK}",
     True),

    ("D09 SSN framed as test/example",
     f"Use {SSN} as the test SSN value in the form.",
     True),

    ("D10 Credit card framed as test checkout data",
     f"Use card {CC} for the test checkout flow.",
     True),


    # ── E: Structural / encoding evasion ────────────────────────────────────

    ("E01 Secret in markdown triple-backtick code block",
     f"```bash\nexport AWS_ACCESS_KEY_ID={AWS_KEY}\n```",
     True),

    ("E02 Secret in inline backtick code",
     f"Run `export TOKEN={GH_PAT}` in your shell.",
     True),

    ("E03 AWS key split across two lines with backslash continuation",
     f"export AWS_KEY=AKIA\\\nY3FDSNDKFKSIDJSW",
     None),

    ("E04 AWS key with internal space",
     "export AWS_KEY=AKIA Y3FDSNDKFKSIDJSW",
     False),

    ("E05 GitHub PAT in JSON string",
     f'{{"token": "{GH_PAT}"}}',
     True),

    ("E06 GitHub PAT in multiline YAML block scalar",
     f"token: |\n  {GH_PAT}\n",
     True),

    ("E07 Stripe key in Python triple-quoted string",
     f'key = """{STRIPE_KEY}"""',
     True),

    ("E08 Stripe key in shell heredoc",
     f"cat <<EOF\nSTRIPE_KEY={STRIPE_KEY}\nEOF",
     True),

    ("E09 AWS key embedded mid-URL path",
     f"https://example.com/keys/{AWS_KEY}/activate",
     None),

    ("E10 Three different secrets in one message",
     f"Setup:\n  AWS: {AWS_KEY}\n  GitHub: {GH_PAT}\n  Stripe: {STRIPE_KEY}",
     True),


    # ── F: Pseudo-secrets / custom credential formats ────────────────────────

    ("F01 Missed case CSKC prefix credential",
     f"here is my new pass {CSKC}",
     True),

    ("F02 MYAPP credential with pwd context",
     f"My app pwd is {MYAPP}",
     True),

    ("F03 INT value with internal token context",
     _j("internal token: INT:", "xK9ScdsJCC", "KLSLKDKasdf12"),
     True),

    ("F04 SDK value",
     _j("SDK:", "xK9mLpQ7vX", "dYeZwBtA5cJf"),
     True),

    ("F05 WHK value signing secret",
     _j("signing secret: WHK:", "xK9mLpQ7vX", "dYeZwBtA5cJfH"),
     True),

    ("F06 DB password with context keyword password",
     _j("password: ", "xK9mLpQ7vXdYe", "ZwBtA5cJf"),
     True),

    ("F07 REF value refresh token",
     _j("refresh token: REF:", "xK9mLpQ7vX", "dYeZwBtA5cJfH"),
     True),

    ("F08 SES value session token",
     _j("session token: SES:", "xK9mLpQ7vX", "dYeZwBtA5cJfH"),
     True),

    ("F09 ENT value enterprise access",
     _j("enterprise access: ENT:", "xK9mLpQ7vX", "dYeZwBtA5cJfH"),
     True),

    ("F10 CLI value client_secret=",
     _j("client_secret=CLI:", "xK9mLpQ7vX", "dYeZwBtA5cJfH"),
     True),


    # ── G: Entropy edge cases ────────────────────────────────────────────────

    ("G01 High-entropy string with secret: prefix",
     f"secret: {HE1}",
     True),

    ("G02 High-entropy string with token= prefix",
     f"token={HE2}",
     True),

    ("G03 High-entropy string with api_key: prefix",
     f"api_key: {HE3}",
     True),

    ("G04 High-entropy string with pwd= prefix",
     f"pwd={HE1}",
     True),

    ("G05 High-entropy string with pass prefix",
     f"pass {HE2}",
     True),

    ("G06 Low-entropy string with password= prefix",
     "password=helloworld",
     None),

    ("G07 High-entropy string with NO context keywords",
     HE1,
     False),

    ("G08 JWT without any surrounding context",
     JWT,
     True),

    ("G09 auth password moderate entropy",
     "auth password: AbCdEfGhIjKlMnOp",
     None),

    ("G10 signing_key= moderate entropy",
     "signing_key=AbCdEfGhIjKlMnOp",
     None),


    # ── H: Active bypass attempts ────────────────────────────────────────────

    ("H01 Misspelled context keyword but Stripe key literal",
     f"passwrod: {STRIPE_KEY}",
     True),

    ("H02 Zero-width space inside AWS key",
     f"key: AKIA\u200bY3FDSNDKFKSIDJSW",
     False),

    ("H03 Mixed-case context keyword PaSsWoRd: + high-entropy",
     f"PaSsWoRd: {HE1}",
     True),

    ("H04 note password docs in one field, GH PAT in another",
     f"note: see password docs for details\ntoken: {GH_PAT}",
     True),

    ("H05 AWS key as part of longer underscore-delimited string",
     f"config_key_{AWS_KEY}_suffix",
     None),

    ("H06 Note: this is NOT a real key + AWS key",
     f"Note: this is NOT a real key — {AWS_KEY}",
     True),

    ("H07 Is X a valid AWS key format? + AWS key",
     f"Is {AWS_KEY} a valid AWS key format?",
     True),

    ("H08 base64 decode this to get the token: + GH_PAT (literal)",
     f"base64 decode this to get the token: {GH_PAT}",
     True),

    ("H09 Secret in parenthetical aside",
     f"Use the API (current key is {STRIPE_KEY}) to call the endpoint.",
     True),

    ("H10 SSN with dots instead of dashes",
     "My SSN is 123.45.6789",
     None),


    # ── I: Clean prompts that must NOT be blocked ────────────────────────────

    ("I01 Normal Python question no secrets",
     "How do I reverse a list in Python?",
     False),

    ("I02 Git concepts question",
     "What is the difference between git rebase and git merge?",
     False),

    ("I03 Conceptual JWT explanation request",
     "Can you explain how JSON Web Tokens work conceptually?",
     False),

    ("I04 Abstract password hashing question",
     "What is the best algorithm for hashing passwords in 2025?",
     False),

    ("I05 AWS IAM roles question no credentials",
     "How do IAM roles differ from IAM users in AWS?",
     False),

    ("I06 Short ambiguous variable name",
     "What does xK9m represent in this context?",
     False),

    ("I07 Version string",
     "I am using version 2.33.1 of git.",
     False),

    ("I08 UUID with dashes",
     "The resource ID is 550e8400-e29b-41d4-a716-446655440000.",
     False),

    ("I09 Git commit hash 40 hex chars",
     "The last commit is 4b825dc642cb6eb9a060e54bf8d69288fbee4904.",
     None),

    ("I10 NOTE colon false-positive test",
     "NOTE: this function is deprecated and will be removed in v3.",
     False),


    # ── J: Sophisticated evasion — format tricks and combined attacks ─────────

    ("J01 Secret after TODO remove-before-commit comment",
     f"# TODO: remove before commit\nAPI_KEY={AWS_KEY}",
     True),

    ("J02 Secret framed as already-redacted placeholder",
     f"STRIPE_KEY=<redacted:{STRIPE_KEY}>",
     True),

    ("J03 Secret as default param in function signature",
     f"def connect(key='{GH_PAT}', region='us-east-1'):",
     True),

    ("J04 Secret in git diff hunk format",
     f"-API_KEY=oldkey123\n+API_KEY={AWS_KEY}",
     True),

    ("J05 Short custom credential below fuzzy min-length (should pass)",
     "KEY:abc123",
     False),

    ("J06 Lowercase prefix colon credential (fuzzy needs uppercase prefix)",
     "myapp:ScdsJCCKLSLKDKLCNLKCEINK2233as",
     False),

    ("J07 Combined SSN + AWS key in same message",
     f"Patient {SSN} has account key {AWS_KEY}",
     True),

    ("J08 Slack token split with surrounding noise text",
     f"The notification service uses ({SLACK_TOK}) for auth.",
     True),

    ("J09 Secret in log-line format with timestamp prefix",
     f"[2024-01-15T12:00:00Z] INFO auth_token={GH_PAT} user=admin",
     True),

    ("J10 Cyrillic homoglyph А in place of Latin A in AWS key prefix",
     f"key=\u0410KIA" + "Y3FDSNDKFKSIDJSW",
     False),
]


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

def run_prompt(prompt: str) -> tuple[bool, str]:
    """Run scanner hook-user-prompt with the given prompt text.

    Returns (blocked, reason). Blocked is True when the scanner emits a block
    decision. reason is the scanner's stated reason or empty string.
    """
    event = {"prompt": prompt}
    result = subprocess.run(
        [sys.executable, str(SCANNER), "hook-user-prompt"],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=30,
    )
    stdout = result.stdout.strip()
    if not stdout:
        return False, ""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return False, f"<unparseable stdout: {stdout[:120]}>"
    decision = data.get("decision", "")
    reason   = data.get("reason", "")
    blocked  = decision == "block"
    return blocked, reason


# ──────────────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────────────

_COL_LABEL   = 44
_COL_BLOCKED = 9
_COL_EXPECT  = 10
_COL_RESULT  = 0   # remainder


def _expect_str(expect: bool | None) -> str:
    if expect is True:
        return "YES"
    if expect is False:
        return "NO"
    return "?"


def _result_str(blocked: bool, expect: bool | None) -> tuple[str, str]:
    """Returns (symbol, tag) for the RESULT column."""
    if expect is None:
        tag = "? UNCERTAIN"
        sym = "?"
    elif blocked and expect:
        tag = "TP"
        sym = "PASS"
    elif not blocked and not expect:
        tag = "TN"
        sym = "PASS"
    elif blocked and not expect:
        tag = "FP"
        sym = "FAIL"
    else:  # not blocked, expect True
        tag = "FN"
        sym = "FAIL"
    return sym, tag


def _outcome(blocked: bool, expect: bool | None) -> str:
    """Map (blocked, expect) to outcome string."""
    if expect is None:
        return "UNCERTAIN"
    if blocked and expect:
        return "TP"
    if not blocked and not expect:
        return "TN"
    if blocked and not expect:
        return "FP"
    return "FN"  # not blocked, expect True


def _outcome_emoji(outcome: str) -> str:
    if outcome in ("TP", "TN"):
        return "✓"
    if outcome in ("FP", "FN"):
        return "⚠"
    return "?"


def _save_json_report(results: list[dict], out_path: Path) -> None:
    """Write the structured JSON report to out_path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tp = sum(1 for r in results if r["outcome"] == "TP")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    uncertain = sum(1 for r in results if r["outcome"] == "UNCERTAIN")
    report = {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(results),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "uncertain": uncertain,
        "results": results,
    }
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def _save_markdown_report(results: list[dict], out_path: Path) -> None:
    """Write a markdown report with a table and sub-sections."""
    tp = sum(1 for r in results if r["outcome"] == "TP")
    tn = sum(1 for r in results if r["outcome"] == "TN")
    fp = sum(1 for r in results if r["outcome"] == "FP")
    fn = sum(1 for r in results if r["outcome"] == "FN")
    uncertain = sum(1 for r in results if r["outcome"] == "UNCERTAIN")

    lines: list[str] = []
    lines.append("# leak-guard Pentest Report\n")
    lines.append(f"**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    lines.append("## Results\n")
    lines.append("| # | Label | Blocked | Expected | Outcome |")
    lines.append("|---|-------|---------|----------|---------|")
    for i, r in enumerate(results, 1):
        blocked_str = "YES" if r["blocked"] else "NO"
        expected_str = {True: "YES", False: "NO", None: "?"}.get(r["expected"], "?")
        emoji = _outcome_emoji(r["outcome"])
        lines.append(f"| {i} | {r['label']} | {blocked_str} | {expected_str} | {emoji} {r['outcome']} |")

    lines.append("\n## Summary\n")
    lines.append(f"- **Total:** {len(results)}")
    lines.append(f"- **True Positives (TP):** {tp}")
    lines.append(f"- **True Negatives (TN):** {tn}")
    lines.append(f"- **False Negatives (FN — MISSES):** {fn}")
    lines.append(f"- **False Positives (FP — NOISE):** {fp}")
    lines.append(f"- **Uncertain:** {uncertain}")

    fn_results = [r for r in results if r["outcome"] == "FN"]
    fp_results = [r for r in results if r["outcome"] == "FP"]
    uc_results = [r for r in results if r["outcome"] == "UNCERTAIN"]

    if fn_results:
        lines.append("\n## False Negatives (MISSES)\n")
        for r in fn_results:
            lines.append(f"- **{r['label']}**")
            lines.append(f"  - Prompt: `{r['prompt'][:120]}`")

    if fp_results:
        lines.append("\n## False Positives (NOISE)\n")
        for r in fp_results:
            lines.append(f"- **{r['label']}**")
            lines.append(f"  - Prompt: `{r['prompt'][:120]}`")

    if uc_results:
        lines.append("\n## Uncertain\n")
        for r in uc_results:
            blocked_str = "BLOCKED" if r["blocked"] else "passed"
            lines.append(f"- **{r['label']}** [{blocked_str}]")
            lines.append(f"  - Prompt: `{r['prompt'][:120]}`")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ask(prompt: str, choices: str = "ynsq") -> str:
    """Prompt with single-letter choices; returns one of choices (lowercase)."""
    valid = set(choices)
    while True:
        try:
            raw = input(f"{prompt} [{'/'.join(choices)}] ").strip().lower()
        except EOFError:
            return "q"
        if raw and raw[0] in valid:
            return raw[0]


def _run_flag(*flag_args: str) -> bool:
    """Invoke scanner.py flag ... ; return True on success."""
    result = subprocess.run(
        [sys.executable, str(SCANNER), "flag", *flag_args],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ✗ flag failed: {result.stderr.strip() or result.stdout.strip()}")
        return False
    out = result.stdout.strip()
    if out:
        print(f"  ✓ {out}")
    else:
        print("  ✓ flagged")
    return True


def _extract_literal(prompt: str) -> str:
    """Best-effort: return the longest contiguous non-space token in prompt.
    Good enough for single-secret prompts; user can edit if needed."""
    tokens = [t.strip("'\"`,;()[]{}<>") for t in prompt.split()]
    return max(tokens, key=len) if tokens else prompt


def _interactive_review(results: list[dict]) -> None:
    targets = [r for r in results if r["outcome"] in ("FP", "FN", "UNCERTAIN")]
    if not targets:
        print("\nNo items to review. ✓")
        return

    print()
    print("=" * 72)
    print(f"REVIEW — {len(targets)} item(s) to triage")
    print("=" * 72)
    print("For each item: y=flag it, n=leave as-is, s=skip, q=quit\n")

    for i, r in enumerate(targets, 1):
        label   = r["label"]
        prompt  = r["prompt"]
        outcome = r["outcome"]
        blocked = r["blocked"]
        preview = prompt if len(prompt) <= 140 else prompt[:137] + "..."

        print(f"[{i}/{len(targets)}] {outcome}  {label}")
        print(f"    prompt: {preview!r}")

        if outcome == "FP":
            # Clean prompt wrongly blocked → allowlist literal
            literal = _extract_literal(prompt)
            print(f"    suggested: allowlist literal {literal!r}")
            ans = _ask("    Allowlist this literal?")
            if ans == "q": break
            if ans == "y":
                _run_flag("fp", "--literal", literal, "--reason", f"pentest {label}")

        elif outcome == "FN":
            # Real secret passed → need a rule. Ask user for rule-id + pattern.
            print("    FN requires a new detection rule (regex).")
            ans = _ask("    Add a custom rule now?")
            if ans == "q": break
            if ans == "y":
                try:
                    rid = input("      rule_id: ").strip()
                    pat = input("      regex  : ").strip()
                    desc = input("      desc   : ").strip() or label
                except EOFError:
                    break
                if rid and pat:
                    _run_flag("fn", "--rule-id", rid, "--pattern", pat,
                              "--description", desc,
                              "--reason", f"pentest {label}")

        else:  # UNCERTAIN
            verdict = _ask(
                f"    Was blocking correct? (blocked={blocked})",
                choices="ynsq",
            )
            if verdict == "q": break
            if verdict == "s" or verdict == "n" and not blocked:
                continue
            if verdict == "y" and blocked:
                print("    → confirmed TP, no action")
                continue
            if verdict == "n" and blocked:
                # It blocked but shouldn't have → treat as FP
                literal = _extract_literal(prompt)
                print(f"    → treating as FP, allowlist {literal!r}")
                sub = _ask("    Proceed?")
                if sub == "y":
                    _run_flag("fp", "--literal", literal,
                              "--reason", f"pentest {label} (uncertain→FP)")
            elif verdict == "y" and not blocked:
                # It passed but should have blocked → FN
                print("    → treating as FN, add a rule")
                try:
                    rid = input("      rule_id: ").strip()
                    pat = input("      regex  : ").strip()
                    desc = input("      desc   : ").strip() or label
                except EOFError:
                    break
                if rid and pat:
                    _run_flag("fn", "--rule-id", rid, "--pattern", pat,
                              "--description", desc,
                              "--reason", f"pentest {label} (uncertain→FN)")
        print()

    print("Review complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="adversarial_suite",
        description="Adversarial pentest suite for leak-guard.",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Save a markdown report to FILE",
    )
    parser.add_argument(
        "--review", action="store_true",
        help="Interactively review FP/FN/UNCERTAIN items and flag them",
    )
    args = parser.parse_args()

    assert len(TESTS) == 100, f"Expected 100 tests, got {len(TESTS)}"  # noqa: S101

    structured_results: list[dict] = []
    display_results: list[tuple[str, bool, bool | None, str, str, str]] = []

    header = (
        f"{'LABEL':<{_COL_LABEL}}"
        f"{'BLOCKED':<{_COL_BLOCKED}}"
        f"{'EXPECTED':<{_COL_EXPECT}}"
        f"RESULT"
    )
    print(header)
    print("-" * (len(header) + 10))

    for label, prompt, expect in TESTS:
        blocked, reason = run_prompt(prompt)
        outcome = _outcome(blocked, expect)
        sym, tag = _result_str(blocked, expect)
        blocked_str = "YES" if blocked else "NO"
        expect_str  = _expect_str(expect)
        result_str  = f"{sym} {tag}"
        print(
            f"{label:<{_COL_LABEL}}"
            f"{blocked_str:<{_COL_BLOCKED}}"
            f"{expect_str:<{_COL_EXPECT}}"
            f"{result_str}"
        )
        display_results.append((label, blocked, expect, reason, sym, tag))
        structured_results.append({
            "label": label,
            "prompt": prompt,
            "blocked": blocked,
            "expected": expect,
            "outcome": outcome,
            "user_flag": None,
            "action": None,
        })

    # ── Summary ──────────────────────────────────────────────────────────────
    tp = sum(1 for _, b, e, _, _, t in display_results if t == "TP")
    tn = sum(1 for _, b, e, _, _, t in display_results if t == "TN")
    fp = sum(1 for _, b, e, _, _, t in display_results if t == "FP")
    fn = sum(1 for _, b, e, _, _, t in display_results if t == "FN")
    uc = sum(1 for _, b, e, _, _, t in display_results if t == "? UNCERTAIN")

    print()
    print("=" * 54 + " SUMMARY " + "=" * 9)
    print(f"Total:         {len(display_results):>4}")
    print(f"True Positive: {tp:>4}  (caught real secrets)")
    print(f"True Negative: {tn:>4}  (clean prompts passed)")
    print(f"False Negative:{fn:>4}  <- MISSES (secrets that slipped through)")
    print(f"False Positive:{fp:>4}  <- NOISE  (clean prompts wrongly blocked)")
    print(f"Uncertain:     {uc:>4}  (no expected value set)")

    if fn:
        print()
        print("-- False Negatives (MISSES) " + "-" * 28)
        for label, blocked, expect, reason, sym, tag in display_results:
            if tag == "FN":
                print(f"  {label}")

    if fp:
        print()
        print("-- False Positives (NOISE) " + "-" * 29)
        for label, blocked, expect, reason, sym, tag in display_results:
            if tag == "FP":
                print(f"  {label}")

    if uc:
        print()
        print("-- Uncertain outcomes " + "-" * 33)
        for label, blocked, expect, reason, sym, tag in display_results:
            if tag == "? UNCERTAIN":
                blocked_str = "BLOCKED" if blocked else "passed"
                print(f"  {label}  [{blocked_str}]")

    # ── Persist JSON report ───────────────────────────────────────────────────
    json_path = Path.home() / ".claude" / "leak-guard" / "last_pentest.json"
    _save_json_report(structured_results, json_path)
    print(f"\nJSON report saved to: {json_path}")

    # ── Interactive review ────────────────────────────────────────────────────
    if args.review:
        _interactive_review(structured_results)

    # ── Optional markdown report ──────────────────────────────────────────────
    if args.output:
        md_path = Path(args.output)
        _save_markdown_report(structured_results, md_path)
        print(f"Markdown report saved to: {md_path}")


if __name__ == "__main__":
    main()
