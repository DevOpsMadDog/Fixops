#!/usr/bin/env python3
import json
import sys

json.dump(
    {"status": 500, "body": {"error": "emr_down", "detail": "EMR maintenance window"}},
    sys.stdout,
    indent=2,
)
