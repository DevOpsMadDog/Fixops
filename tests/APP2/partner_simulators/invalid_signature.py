#!/usr/bin/env python3
import json
import time

payload = {
    "event_id": "invalid-%d" % int(time.time()),
    "type": "offer.updated",
    "payload": {
        "offer_id": "OFF-INVALID",
        "price": 99.0,
        "currency": "USD"
    },
    "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
}

print(json.dumps({
    "timestamp": str(int(time.time())),
    "signature": "deadbeef",
    "body": payload
}, indent=2))
