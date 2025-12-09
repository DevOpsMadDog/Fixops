#!/usr/bin/env python3
import json
import time

print(
    json.dumps(
        {
            "timestamp": str(int(time.time())),
            "signature": "invalid",
            "body": {
                "message_id": "bad-1",
                "resourceType": "Observation",
                "patient": "PAT-0000",
                "value": 120,
                "unit": "bpm",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        },
        indent=2,
    )
)
