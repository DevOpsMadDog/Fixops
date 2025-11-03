#!/usr/bin/env python3
import json
import sys

json.dump({
    "status": 429,
    "retry_after": 60,
    "body": {
        "error": "rate_limited",
        "detail": "HL7 feed exceeded contract"
    }
}, sys.stdout, indent=2)
