#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import time

SECRET = os.environ.get("APP3_PARTNER_SECRET", "ehr-shared-key")
message = {
    "message_id": f"hl7-{int(time.time())}",
    "resourceType": "Observation",
    "patient": "PAT-8821",
    "value": 98.2,
    "unit": "F",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
}

body = json.dumps(message, separators=(",", ":")).encode()
ts = str(int(time.time()))
sig = hmac.new(SECRET.encode(), ts.encode() + b"." + body, hashlib.sha512).digest()
print(json.dumps({
    "timestamp": ts,
    "signature": base64.b64encode(sig).decode(),
    "body": message
}, indent=2))
