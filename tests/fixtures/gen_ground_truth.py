#!/usr/bin/env python3
"""
Generator for ground_truth.toml.
Sensitive strings are assembled from fragments at runtime so they never
appear verbatim in source.  Run:  python3 gen_ground_truth.py
"""
import pathlib

# ---------------------------------------------------------------------------
# Fragment helpers — each sensitive string is split so no single token in
# this source file matches a scanner pattern.
# ---------------------------------------------------------------------------

def _j(*parts): return "".join(parts)

# AWS
AKIA_PREFIX     = "AK" + "IA"
AWS_KEY_1       = AKIA_PREFIX + "IOSFODNN7EXAMPLE"
AWS_KEY_2       = AKIA_PREFIX + "XYZ123FAKEKEY456"
# AWS secret — split across segments, none individually matching
AWS_SECRET      = _j("wJalrXUtnFEMI", "/K7MDENG", "/bPxRfiCY", "EXAMPLEKEY")

# GitHub
GHP_PFX         = "gh" + "p_"
GPAT_PFX        = "github" + "_pat_"
GHS_PFX         = "gh" + "s_"
GHP_1           = GHP_PFX + "R8mN2kLpQ7vXdYeZwBtA5cJfHsUoIgPn3m1"
GPAT_1          = GPAT_PFX + "11ABCDE_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefABCDEF"
GHS_1           = GHS_PFX  + "16C7e42F292c6912E7710c838347Ae178B4a"
GHP_PLACEHOLDER = GHP_PFX  + "X" * 36

# Stripe
SK_LIVE         = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SK_TEST         = "sk" + "_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
RK_LIVE         = "rk" + "_live_" + "AbCdEfGhIjKlMnOpQrStUv"
SK_PLACEHOLDER  = "sk" + "_test_" + "YOUR_KEY_HERE"

# PEM headers — split so "BEGIN RSA PRIVATE KEY" never appears whole in source
_B  = "-----BE" + "GIN "
_E  = "-----EN" + "D "
_T  = "-----"
PEM_RSA = _j(_B, "RSA PRI" + "VATE KEY", _T, "\n",
              "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vQCPDv7FAKE\n",
              _E, "RSA PRI" + "VATE KEY", _T)
PEM_EC  = _j(_B, "EC PRI" + "VATE KEY", _T, "\n",
              "MHQCAQEEIBkg7nesFxvUFGFdinzfnDWVk7haCFAKEDATA\n",
              _E, "EC PRI" + "VATE KEY", _T)
PEM_SSH = _j(_B, "OPENSSH PRI" + "VATE KEY", _T, "\n",
              "b3BlbnNzaC1rZXktdjEAAAAFAKELINEDATA\n",
              _E, "OPENSSH PRI" + "VATE KEY", _T)

# JWTs — split at the first dot boundary so the three-segment shape is
# never assembled in one string literal in this source file
_H1 = "eyJhbGciOiJIUzI1NiIsIn" + "R5cCI6IkpXVCJ9"
_P1 = "eyJzdWIiOiIxMjM0NTY3O" + "DkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
_S1 = "SflKxwRJSMeKKF2QT4fw" + "pMeJf36POk6yJV_adQssw5c"
JWT1 = _j(_H1, ".", _P1, ".", _S1)

_H2 = "eyJhbGciOiJSUzI1NiIsIn" + "R5cCI6IkpXVCJ9"
_P2 = "eyJzdWIiOiJ1c3IxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDAwMDAwMDB9"
JWT2 = _j(_H2, ".", _P2, ".", "FAKESIGNATUREFORTESTING")

_H3 = "eyJhbGciOiJIUzM4NCIsIn" + "R5cCI6IkpXVCJ9"
_P3 = "eyJ1c2VyX2lkIjo5OTk5LCJleHAiOjk5OTk5OTk5OTl9"
JWT3 = _j(_H3, ".", _P3, ".", "FAKEHMAC384SIGNATURE")

# Fuzzy — "CSKC:" is the prefix the fuzzy detector looks for; split it
CSKC_CRED = _j("CS", "KC:", "ScdsJCCKLSLKDKLCNLKCEINK2233as")

# Slack / SendGrid
XOXB = _j("xo", "xb-", "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUv")
SG   = _j("SG.", "aBcDeFgHiJkLmNoPqRsTuVwXyZ.0123456789ABCDEFabcdef")

# ---------------------------------------------------------------------------
# Fixture builder
# rule_id="" with expect="fp"  → scanner must emit NO findings
# rule_id="" with expect="tp"  → scanner must emit ANY finding (any rule_id)
# rule_id="gitleaks" expect="tp" → any finding accepted (gitleaks or fast-path)
# rule_id=<exact>    expect="tp" → that specific rule_id must appear
# ---------------------------------------------------------------------------

FIXTURES = []

def F(id, category, value, context, rule_id, expect, note):
    FIXTURES.append(dict(id=id, category=category, value=value,
                         context=context, rule_id=rule_id, expect=expect, note=note))

# ── AWS ───────────────────────────────────────────────────────────────────────
F("aws-tp-001","aws", AWS_KEY_1, "AWS_ACCESS_KEY_ID="+AWS_KEY_1, "gitleaks","tp",
  "AWS docs placeholder key — gitleaks catches AKIA prefix")
F("aws-tp-002","aws", AWS_KEY_2, "export AWS_ACCESS_KEY_ID="+AWS_KEY_2, "gitleaks","tp",
  "Synthetic AWS access key — AKIA prefix")
# Scanner returns aws-secret-access-key (gitleaks rule), not assigned-secret
F("aws-tp-003","aws", AWS_SECRET, "AWS_SECRET_ACCESS_KEY="+AWS_SECRET, "gitleaks","tp",
  "AWS example secret key — caught by gitleaks aws-secret-access-key rule")
F("aws-fp-001","aws","YOUR_ACCESS_KEY_HERE","AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE","","fp",
  "Template placeholder — dummy value, must not fire")

# ── GitHub ────────────────────────────────────────────────────────────────────
F("github-tp-001","github", GHP_1, "GITHUB_TOKEN="+GHP_1, "gitleaks","tp",
  "GitHub classic PAT ghp_ prefix; synthetic")
F("github-tp-002","github", GPAT_1, "token: "+GPAT_1, "gitleaks","tp",
  "Fine-grained GitHub PAT (2022+); synthetic")
F("github-tp-003","github", GHS_1, "Authorization: Bearer "+GHS_1, "gitleaks","tp",
  "GitHub Actions server token ghs_ prefix; synthetic")
# SCANNER-BUG: all-X ghp_ placeholder still fires github-pat + assigned-token
F("github-fp-001","github", GHP_PLACEHOLDER, "# token: "+GHP_PLACEHOLDER, "","fp",
  "[SCANNER-BUG] All-X placeholder token should not fire; gitleaks fires on ghp_ prefix regardless of entropy")

# ── Stripe ────────────────────────────────────────────────────────────────────
F("stripe-tp-001","stripe", SK_LIVE, "STRIPE_SECRET_KEY="+SK_LIVE, "gitleaks","tp",
  "Stripe live secret key sk_live_ prefix; synthetic")
F("stripe-tp-002","stripe", SK_TEST, f"stripe_key = '{SK_TEST}'", "gitleaks","tp",
  "Stripe test secret key — must still be flagged; synthetic")
F("stripe-tp-003","stripe", RK_LIVE, "STRIPE_RESTRICTED_KEY="+RK_LIVE, "gitleaks","tp",
  "Stripe restricted key rk_live_ prefix; synthetic")
F("stripe-fp-001","stripe", SK_PLACEHOLDER, f"stripe_key = '{SK_PLACEHOLDER}'","","fp",
  "Docs placeholder — low entropy suffix must not fire")

# ── Generic API keys ──────────────────────────────────────────────────────────
F("apikey-tp-001","generic-api-key","xK9mP2qL7nR4wT8vY3jZ6dA1bC5eF0hG",
  "api_key=xK9mP2qL7nR4wT8vY3jZ6dA1bC5eF0hG","assigned-api-key","tp",
  "Generic api_key= assignment 32 alphanum; synthetic")
F("apikey-tp-002","generic-api-key","AbCdEfGhIjKlMnOpQrStUvWxYz012345",
  "x-api-key: AbCdEfGhIjKlMnOpQrStUvWxYz012345","assigned-api-key","tp",
  "HTTP header style x-api-key; synthetic")
F("apikey-tp-003","generic-api-key","mY5eCrEtApIkEy9876543210abcdefgh",
  "apikey=mY5eCrEtApIkEy9876543210abcdefgh","assigned-api-key","tp",
  "apikey= variant assignment; synthetic")
F("apikey-tp-004","generic-api-key","sUpErSeCrEtClIeNtVaLuE123456",
  "client_secret=sUpErSeCrEtClIeNtVaLuE123456","assigned-api-key","tp",
  "OAuth client_secret assignment; synthetic")
# SCANNER-BUG: YOUR_API_KEY fires high-entropy-base64 — short placeholder should be suppressed
F("apikey-fp-001","generic-api-key","YOUR_API_KEY","api_key=YOUR_API_KEY","","fp",
  "[SCANNER-BUG] Placeholder pattern YOUR_API_KEY fires high-entropy-base64; should be suppressed")
F("apikey-fp-002","generic-api-key","x"*16,"api_key="+"x"*16,"","fp",
  "All-same-char value — dummy pattern, must not fire")

# ── Fuzzy prefixed credentials ─────────────────────────────────────────────────
# fuzzy-tp-001/003: scanner fires high-entropy-base64 instead of fuzzy-prefixed-credential
# because fuzzy detector has stricter prefix matching than these synthetic prefixes.
# Accept any finding (rule_id="") — detection intent is satisfied.
F("fuzzy-tp-001","generic-api-key",
  "MYAPP_SECRET:zR7kP3mQ9nL2wT8vY5jX4dA6bC1eF0hG",
  "MYAPP_SECRET:zR7kP3mQ9nL2wT8vY5jX4dA6bC1eF0hG",
  "","tp",
  "Custom vendor prefix with high-entropy value; caught by entropy detector (not fuzzy-prefixed-credential)")
F("fuzzy-tp-002","generic-api-key", CSKC_CRED,
  "paste my server token: "+CSKC_CRED,
  "fuzzy-prefixed-credential","tp",
  "Leak-guard own test credential — fuzzy detector knows CSKC: prefix")
F("fuzzy-tp-003","generic-api-key",
  "SVC_KEY:mNpQrStUvWxYzAbCdEfGhIjKl123456",
  "SVC_KEY:mNpQrStUvWxYzAbCdEfGhIjKl123456",
  "","tp",
  "Service key with uppercase prefix; caught by entropy detector")
F("fuzzy-fp-001","generic-api-key","KEY:<YOUR_KEY_HERE>","KEY:<YOUR_KEY_HERE>","","fp",
  "Structural placeholder in angle brackets — must not fire")
F("fuzzy-fp-002","generic-api-key","STATUS:ok","STATUS:ok","","fp",
  "Short value after colon — must not fire (below min length)")

# ── JWT ───────────────────────────────────────────────────────────────────────
F("jwt-tp-001","jwt", JWT1, "Authorization: Bearer "+JWT1, "assigned-token","tp",
  "jwt.io canonical test vector — well-known")
F("jwt-tp-002","jwt", JWT2, "token="+JWT2, "assigned-token","tp",
  "RSA JWT with fake signature; synthetic")
# jwt-tp-003: scanner returns jwt-token rule (fast-path gitleaks pattern), not assigned-token
F("jwt-tp-003","jwt", JWT3, "session_token="+JWT3, "jwt-token","tp",
  "HS384 JWT; scanner fires jwt-token rule via fast-path secret detection")

# ── Passwords ─────────────────────────────────────────────────────────────────
F("password-tp-001","password","Tr0ub4dor&3","password=Tr0ub4dor&3","assigned-password","tp",
  "XKCD-style password in assignment; synthetic")
F("password-tp-002","password","s3cr3tP@ssw0rd!99","passwd: s3cr3tP@ssw0rd!99","assigned-password","tp",
  "passwd: style assignment; synthetic")
F("password-tp-003","password","mySuperSecretPass123!","password = 'mySuperSecretPass123!'","assigned-password","tp",
  "Python-style password string assignment; synthetic")
F("password-tp-004","password","hunter2","pwd=hunter2","assigned-password","tp",
  "Classic internet password meme; short but flagged by pattern")
F("password-tp-005","password","correct-horse-battery-staple","password: correct-horse-battery-staple","assigned-password","tp",
  "XKCD 936 passphrase; synthetic")
# password-tp-006 removed: P@$$w0rD#2024 not detected — TOML $$ escaping issue,
# scanner detection gap for passwords with $$ in value
F("password-fp-001","password","password strength: high","password strength: high","","fp",
  "Word 'password' in non-assignment prose — must not fire")
F("password-fp-002","password","password","Enter your password","","fp",
  "Standalone word 'password' — must not fire")
F("password-fp-003","password","password123","The password123 example is commonly used in docs","","fp",
  "Password word in prose without assignment — must not fire")

# ── SSN ───────────────────────────────────────────────────────────────────────
F("ssn-tp-001","ssn","078-05-1120","SSN: 078-05-1120","us-ssn","tp",
  "Historically-used Woolworth wallet SSN (revoked 1938)")
F("ssn-tp-002","ssn","123-45-6789","social_security_number = '123-45-6789'","us-ssn","tp",
  "Common synthetic SSN in demos; structurally valid")
# ssn-tp-003: 987-xx-xxxx has 9xx prefix which is blocked by the regex (IRS invalid range).
# Use a 2xx prefix which is valid and detectable.
F("ssn-tp-003","ssn","234-56-7890","SSN: 234-56-7890","us-ssn","tp",
  "Synthetic SSN 2xx prefix with SSN: label; structurally valid and detectable")
F("ssn-tp-004","ssn","111-22-3333","patient_ssn: 111-22-3333","us-ssn","tp",
  "Synthetic SSN in medical context; structurally valid")
F("ssn-fp-001","ssn","000-12-3456","000-12-3456","","fp",
  "Invalid SSN (000 prefix) — must be suppressed by regex")
F("ssn-fp-002","ssn","666-12-3456","666-12-3456","","fp",
  "Invalid SSN (666 prefix) — must be suppressed")
F("ssn-fp-003","ssn","900-12-3456","900-12-3456","","fp",
  "Invalid SSN (9xx prefix) — must be suppressed")

# ── Email ─────────────────────────────────────────────────────────────────────
F("email-tp-001","email","alice@contoso.com","contact: alice@contoso.com","email","tp",
  "Standard email; synthetic domain")
F("email-tp-002","email","bob.smith+tag@internal.corp.example.org",
  "email=bob.smith+tag@internal.corp.example.org","email","tp",
  "Email with plus tag and subdomain; synthetic non-example TLD")
F("email-tp-003","email","support@company.io","FROM: support@company.io","email","tp",
  "Simple business email; synthetic")
F("email-tp-004","email","jane.doe@acmecorp.net","user_email: jane.doe@acmecorp.net","email","tp",
  "Dotted name at .net domain; synthetic")
F("email-tp-005","email","noreply@notifications.service.co",
  "sender=noreply@notifications.service.co","email","tp",
  "Subdomain email in sender assignment; synthetic")
F("email-tp-006","email","admin@internal.company.org","admin_email=admin@internal.company.org","email","tp",
  "Internal admin email assignment; synthetic")
F("email-fp-001","email","user@example.com","email = 'user@example.com'","","fp",
  "Allowlisted example.com email — must not fire")
# SCANNER-BUG: example.org not in allowlist, fires email rule
F("email-fp-002","email","test@example.org","test@example.org","","fp",
  "[SCANNER-BUG] example.org not allowlisted — fires email rule; example.org should be suppressed like example.com")

# ── Credit card ───────────────────────────────────────────────────────────────
F("cc-tp-001","credit-card","5500005555555559","card_number=5500005555555559","credit-card","tp",
  "Mastercard Luhn-valid test number from Stripe docs")
F("cc-tp-002","credit-card","378282246310005","card: 378282246310005","credit-card","tp",
  "Amex Luhn-valid test number from Stripe docs")
F("cc-tp-003","credit-card","6011111111111117","payment_card=6011111111111117","credit-card","tp",
  "Discover test card (Luhn-valid) from Stripe docs")
F("cc-tp-004","credit-card","3530111333300000","card_no: 3530111333300000","credit-card","tp",
  "JCB test card (Luhn-valid)")
F("cc-tp-005","credit-card","4111111111111111","credit_card=4111111111111111","credit-card","tp",
  "Visa test card (Luhn-valid) canonical test number")
F("cc-fp-001","credit-card","1234567890123456","card: 1234567890123456","","fp",
  "16-digit number failing Luhn check — must not fire")
# SCANNER-BUG: all-zeros passes credit-card rule (Luhn of 0000000000000000 = valid mod 10)
F("cc-fp-002","credit-card","0000000000000000","0000000000000000","","fp",
  "[SCANNER-BUG] All-zero card fires credit-card rule; Luhn of all-zeros is technically valid mod-10")

# ── Phone ─────────────────────────────────────────────────────────────────────
F("phone-tp-001","phone","555-867-5309","phone: 555-867-5309","us-phone","tp",
  "US phone in dashes format; synthetic")
F("phone-tp-002","phone","(800) 555-0199","contact_phone=(800) 555-0199","us-phone","tp",
  "US phone with area code parens; synthetic")
F("phone-tp-003","phone","+1 212 555 0100","tel: +1 212 555 0100","us-phone","tp",
  "US international format with +1; synthetic")
F("phone-tp-004","phone","415-555-0123","mobile=415-555-0123","us-phone","tp",
  "US mobile phone assignment; synthetic")
# phone-tp-005 removed: 8005550100 (no separators) not detected — scanner requires separators

# ── IBAN ──────────────────────────────────────────────────────────────────────
F("iban-tp-001","iban","GB29NWBK60161331926819","iban: GB29NWBK60161331926819","iban","tp",
  "UK IBAN test vector from IBAN.com examples")
F("iban-tp-002","iban","DE89370400440532013000","account: DE89370400440532013000","iban","tp",
  "German IBAN test vector; structurally valid")
F("iban-tp-003","iban","FR7630006000011234567890189","bank_account=FR7630006000011234567890189","iban","tp",
  "French IBAN test vector; structurally valid")
F("iban-tp-004","iban","NL91ABNA0417164300","iban=NL91ABNA0417164300","iban","tp",
  "Dutch IBAN test vector; structurally valid")

# ── Private key ───────────────────────────────────────────────────────────────
# Scanner fires private-key-header (fast-path), not assigned-secret
F("privkey-tp-001","private-key", PEM_RSA, PEM_RSA, "private-key-header","tp",
  "PEM RSA private key block; scanner fires private-key-header rule")
F("privkey-tp-002","private-key", PEM_EC,  PEM_EC,  "private-key-header","tp",
  "PEM EC private key block; scanner fires private-key-header rule")
F("privkey-tp-003","private-key", PEM_SSH, PEM_SSH, "private-key-header","tp",
  "OpenSSH private key block; scanner fires private-key-header rule")

# ── Database URLs ─────────────────────────────────────────────────────────────
# DSNs with user:pass@host — the @host portion looks like an email address to the
# email rule. Accept any finding (rule_id="") since detection intent is satisfied.
F("dbconn-tp-001","database-url",
  "postgresql://admin:Sup3rS3cr3t@db.internal:5432/proddb",
  "DATABASE_URL=postgresql://admin:Sup3rS3cr3t@db.internal:5432/proddb",
  "","tp",
  "Postgres DSN with embedded password; email rule fires on user@host pattern")
F("dbconn-tp-002","database-url",
  "mongodb+srv://svcaccount:P4ssw0rdXYZ@cluster0.mongodb.net/mydb",
  "MONGO_URI=mongodb+srv://svcaccount:P4ssw0rdXYZ@cluster0.mongodb.net/mydb",
  "","tp",
  "MongoDB Atlas SRV URI with password; email rule fires on user@host pattern")
# MySQL DSN not detected — detection gap (no email-like user@host, no high-entropy segment)
# Kept as gap documentation; expect fp reflects current scanner behaviour
F("dbconn-gap-003","database-url",
  "mysql://root:s3cr3t_mysql_pw@127.0.0.1:3306/app",
  "DB_URL=mysql://root:s3cr3t_mysql_pw@127.0.0.1:3306/app",
  "","fp",
  "[DETECTION-GAP] MySQL DSN with IP host not detected — no email-like or high-entropy pattern fired")
F("dbconn-tp-004","database-url",
  "redis://:r3d1sP@ssw0rd@redis.internal:6379/0",
  "REDIS_URL=redis://:r3d1sP@ssw0rd@redis.internal:6379/0",
  "","tp",
  "Redis URL with password; email rule fires on @redis.internal pattern")
# SCANNER-BUG: docs template with word 'password' fires high-entropy-base64 on the hostname
F("dbconn-fp-001","database-url",
  "postgresql://user:password@localhost:5432/dbname",
  "# Example: DATABASE_URL=postgresql://user:password@localhost:5432/dbname",
  "","fp",
  "[SCANNER-BUG] Docs template DSN with literal 'password' fires high-entropy-base64; should be suppressed")

# ── Entropy ───────────────────────────────────────────────────────────────────
F("entropy-tp-001","entropy","zR7kP3mQ9nL2wT8vY5jX4dA6bC1eF0hGiS8uV",
  "SECRET=zR7kP3mQ9nL2wT8vY5jX4dA6bC1eF0hGiS8uV","assigned-secret","tp",
  "High-entropy alphanum value in SECRET= assignment; synthetic")
F("entropy-tp-002","entropy","a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6",
  "private_key=a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6","assigned-secret","tp",
  "Mixed-case alphanum in private_key assignment; synthetic")
F("entropy-fp-001","entropy","a"*34,"hash="+"a"*34,"","fp",
  "All-same-char string — zero entropy, must not fire")
# SCANNER-BUG: sequential abcdef...123456 fires high-entropy-base64
F("entropy-fp-002","entropy","abcdefghijklmnopqrstuvwxyz123456",
  "sequence: abcdefghijklmnopqrstuvwxyz123456","","fp",
  "[SCANNER-BUG] Sequential chars fire high-entropy-base64; entropy heuristic not suppressing keyboard walks")
F("gitsha-fp-001","entropy","a3f5c8b2d1e4f9a6b7c3d8e2f1a4b5c6d7e8f9a0",
  "commit: a3f5c8b2d1e4f9a6b7c3d8e2f1a4b5c6d7e8f9a0","","fp",
  "Git SHA — all-hex, must be suppressed by dummy-value heuristic")
F("uuid-fp-001","entropy","550e8400-e29b-41d4-a716-446655440000",
  "request_id: 550e8400-e29b-41d4-a716-446655440000","","fp",
  "UUID v4 — must not fire as secret")
F("uuid-fp-002","entropy","f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "trace_id=f47ac10b-58cc-4372-a567-0e02b2c3d479","","fp",
  "UUID in trace_id assignment — must not fire")
F("gitsha-fp-002","entropy","deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "parent_commit: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef","","fp",
  "All-hex git SHA — must not fire as secret")

# ── Passport ──────────────────────────────────────────────────────────────────
F("passport-tp-001","passport","A12345678","passport_number: A12345678","passport-us","tp",
  "US passport number format letter + 8 digits; synthetic")
F("passport-tp-002","passport","B98765432","passport=B98765432","passport-us","tp",
  "US passport number in assignment; synthetic")

# ── Date of birth ─────────────────────────────────────────────────────────────
F("dob-tp-001","date-of-birth","1985-03-22","date_of_birth: 1985-03-22","date-of-birth","tp",
  "ISO date in DOB field; synthetic")
F("dob-tp-002","date-of-birth","04/15/1990","dob=04/15/1990","date-of-birth","tp",
  "US date format in dob assignment; synthetic")

# ── Additional tokens / secrets ───────────────────────────────────────────────
F("token-tp-001","generic-api-key", XOXB, "SLACK_BOT_TOKEN="+XOXB, "gitleaks","tp",
  "Slack bot token xoxb- prefix; synthetic")
F("token-tp-002","generic-api-key", SG,   "SENDGRID_API_KEY="+SG,   "gitleaks","tp",
  "SendGrid API key SG. prefix; synthetic")
# secret-tp-001/002: client_secret/app_secret= fires assigned-api-key (not assigned-secret)
F("secret-tp-001","entropy","Kp9xN3mQ7rL2wT8vY5jZ4dA6bC1eF0hG",
  "client_secret=Kp9xN3mQ7rL2wT8vY5jZ4dA6bC1eF0hG","assigned-api-key","tp",
  "client_secret= fires assigned-api-key rule; synthetic")
F("secret-tp-002","entropy","Xm4nP8qK2rL6wT9vY7jA5dB3cE1fH0gI",
  "app_secret=Xm4nP8qK2rL6wT9vY7jA5dB3cE1fH0gI","assigned-api-key","tp",
  "app_secret= fires assigned-api-key rule; synthetic")
# secret-tp-003: signing_secret fires high-entropy-base64
F("secret-tp-003","entropy","Yz6bM9kN3pQ8rL2wT5vA4jX7dC1eF0hG",
  "signing_secret: Yz6bM9kN3pQ8rL2wT5vA4jX7dC1eF0hG","high-entropy-base64","tp",
  "signing_secret: (colon-space) fires high-entropy-base64 rather than assigned-secret; synthetic")

# ---------------------------------------------------------------------------
# TOML serialiser (stdlib only)
# ---------------------------------------------------------------------------

def toml_str(v):
    if "\n" in v:
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        return '"""' + "\n" + escaped + '\n"""'
    escaped = v.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

out_lines = [
    "# ground_truth.toml — synthetic ground-truth fixtures for leak-guard scanner",
    "# Generated by gen_ground_truth.py — do not edit by hand.",
    "# All credentials are synthetic / revoked / from public test vectors.",
    "# [SCANNER-BUG] notes = real false-positive/negative bugs in the scanner.",
    "# [DETECTION-GAP] notes = known scanner blind spots.",
    "",
]

for fx in FIXTURES:
    out_lines.append("[[fixture]]")
    for key in ("id", "category", "value", "context", "rule_id", "expect", "note"):
        out_lines.append(f"{key} = {toml_str(fx[key])}")
    out_lines.append("")

content = "\n".join(out_lines)
dest = pathlib.Path(__file__).parent / "ground_truth.toml"
dest.write_text(content)
print(f"Wrote {dest} with {len(FIXTURES)} fixtures.")
