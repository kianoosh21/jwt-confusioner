# JWT Confusioner

**Automated JWT verification & fuzzing harness** for security teams.  
JWT Confusioner discovers signing keys, verifies a valid token, and generates a comprehensive suite of **malicious or malformed JWTs** designed to test whether your server is immune to JWT confusion and validation bypass attacks.

> ⚠️ **Ethical Use Only:** Use JWT Confusioner strictly on systems you own or have explicit authorization to test.

---

## What it does

1. **Parses** a provided JWT (header, payload, signature).  
2. **Discovers JWKS** automatically from the `iss` claim (via OIDC discovery → `/.well-known/openid-configuration` → `jwks_uri`; fallback to `/.well-known/jwks.json`).  
3. **Fetches JWKS** and selects the correct key by `kid`/`alg`.  
4. **Verifies** the original JWT signature.  
5. **Crafts a suite** of malicious JWTs to check for signature confusion, algorithm downgrades, key misuse, and validation errors.  
6. **Outputs** all crafted tokens to `tokens.json` and prints a summary table.

---

## Features

- **Full JWKS Discovery** (OIDC + fallback).  
- **Automatic Signature Verification** of original JWT.  
- **Comprehensive Fuzzing Tests**:
  - HS256 / ES256 **confusion attacks** (using public key as HMAC secret)
  - `alg=none` bypass attempts
  - Wrong-algorithm substitutions (`RS256`, `PS256`, `ES384`, `HS384`, etc.)
  - Claim tampering (`iss`, `aud`, `exp`, `nbf`, `jti`)
  - RFC 7797 “unencoded payload” attacks
  - Header injection / key-fetch abuse (`kid`, `jku`, `x5u`)
- **Readable Output** via `--pretty-blank-lines`.  
- **Detailed `-h` Manual** with usage and test IDs.

---

## How it works

- Extracts `iss` and `kid` from your JWT.  
- Auto-discovers the JWKS endpoint of your issuer.  
- Validates the JWT signature using PyJWT and the discovered key.  
- Generates forged tokens by altering headers, algorithms, claims, or signatures.  
- These new tokens simulate **real-world JWT attacks** your server should reject.

---

## Installation

    python3 -m venv venv && source venv/bin/activate
    pip install pyjwt cryptography requests

Script name: `jwt-confusioner.py`

---

## Quick Start

    # 1) Verify the JWT and generate a test suite
    python3 jwt-confusioner.py -t '<YOUR_JWT>'

    # 2) Print decoded header/payload and save crafted tokens to a file
    python3 jwt-confusioner.py -t '<YOUR_JWT>' --print-payload -o tokens.json

    # 3) Produce a more readable tokens.json (adds blank lines between entries)
    python3 jwt-confusioner.py -t '<YOUR_JWT>' --pretty-blank-lines

---

## Usage (CLI)

    python3 jwt-confusioner.py -h

Available flags:

    -t, --token                  (required) Input JWT.
    --aud <audience>             Enforce audience when verifying the original token.
    --jwks-uri <url>             Override JWKS endpoint (skip discovery).
    --include <ids>              Comma-separated test IDs to include.
    --exclude <ids>              Comma-separated test IDs to exclude.
    --timeout <sec>              HTTP timeout (default: 10).
    --insecure                   Disable TLS verification for JWKS fetch (NOT recommended).
    --print-payload              Pretty-print decoded JWT header and payload.
    -o, --out <file>             Output file (default: tokens.json).
    --pretty-blank-lines         Write tokens.json with blank lines between entries.

---

## Test Matrix

HS256 Confusion
- hs256_confusion_pem_bytes     → alg=HS256, HMAC secret = PEM bytes of public key  
- hs256_confusion_der_bytes     → alg=HS256, HMAC secret = DER bytes of public key  
- hs256_confusion_keep_kid      → same as above, keeps original kid

Algorithm Misconfiguration
- alg_none                      → alg=none (no signature)  
- wrong_alg_RS256               → replaced with RS256  
- wrong_alg_PS256               → replaced with PS256  
- wrong_alg_ES384               → replaced with ES384  
- wrong_alg_ES512               → replaced with ES512  
- wrong_alg_HS384               → replaced with HS384 (dummy signature)

Claim Tampering
- tamper_iss                    → forged issuer  
- tamper_aud                    → forged audience  
- tamper_expired                → expired exp  
- tamper_nbf_future             → nbf in the future  
- tamper_jti_new                → new random jti (replay test)

Header / JWKS Abuse
- crit_b64_false_unencoded_payload → RFC 7797 unencoded payload (b64:false)  
- kid_traversal                     → kid="../../etc/passwd"  
- kid_absolute_path                 → kid="/var/www/keys/priv.pem"  
- kid_url                           → kid="http://attacker.invalid/evil"  
- jku_external                      → jku="http://attacker.invalid/jwks.json"  
- x5u_external                      → x5u="http://attacker.invalid/cert.pem"

✅ A secure implementation must **reject all** crafted tokens above.

---

## Example Workflow

    # Generate and save crafted tokens
    python3 jwt-confusioner.py -t '<YOUR_JWT>' --pretty-blank-lines -o tokens.json

    # Use each token in your API tests
    # Example: Authorization: Bearer <token>
    # Assert your API returns 401/403 for all crafted tokens.

---

## Screenshots

    CLI Help:
      ![CLI Help](/home/kali/BBP/Moonpig/Archive/test/jwt-confusioner/docs/1.png)

    Sample Run:
      ![Sample Run](/home/kali/BBP/Moonpig/Archive/test/jwt-confusioner/docs/2.png)

    Sample Run:
      ![Sample Results](/home/kali/BBP/Moonpig/Archive/test/jwt-confusioner/docs/3.png)
