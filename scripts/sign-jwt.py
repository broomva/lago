#!/usr/bin/env python3
"""Sign a Lago JWT for admin operations.

Usage: LAGO_JWT_SECRET=<secret> python3 sign-jwt.py

Outputs a JWT suitable for Bearer authentication with lagod.
"""
import json
import hmac
import hashlib
import base64
import time
import os
import sys

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

secret = os.environ.get("LAGO_JWT_SECRET")
if not secret:
    print("Error: LAGO_JWT_SECRET not set", file=sys.stderr)
    sys.exit(1)

header = {"alg": "HS256", "typ": "JWT"}
now = int(time.time())
payload = {
    "sub": "admin",
    "email": "admin@broomva.tech",
    "iat": now,
    "exp": now + 86400,  # 24 hours
}

header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
signing_input = f"{header_b64}.{payload_b64}"
signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
sig_b64 = b64url(signature)

print(f"{signing_input}.{sig_b64}")
