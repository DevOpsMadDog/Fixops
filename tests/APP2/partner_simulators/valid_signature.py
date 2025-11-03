#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import time
from typing import Tuple

SECRET = os.environ.get("APP2_PARTNER_SECRET", "super-secret-key")

EVENT = {
    "event_id": "e-%d" % int(time.time()),
    "type": "offer.created",
    "payload": {
        "offer_id": "OFF-%d" % int(time.time()),
        "price": 199.0,
        "currency": "USD"
    },
    "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
}


def sign(event: dict) -> Tuple[str, str]:
    body = json.dumps(event, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(SECRET.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return timestamp, signature


def main():
    ts, sig = sign(EVENT)
    print(json.dumps({"timestamp": ts, "signature": sig, "body": EVENT}, indent=2))


if __name__ == "__main__":
    main()
