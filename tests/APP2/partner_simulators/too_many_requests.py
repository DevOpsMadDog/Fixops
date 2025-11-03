#!/usr/bin/env python3
import json
import sys

response = {
    "status": 429,
    "retry_after": 30,
    "body": {
        "error": "rate_limited",
        "detail": "Exceeded contract burst limit"
    }
}
json.dump(response, sys.stdout, indent=2)
