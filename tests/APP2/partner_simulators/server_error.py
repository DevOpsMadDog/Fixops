#!/usr/bin/env python3
import json
import sys

response = {
    "status": 500,
    "body": {
        "error": "internal_error",
        "detail": "Partner upstream database maintenance",
    },
}
json.dump(response, sys.stdout, indent=2)
