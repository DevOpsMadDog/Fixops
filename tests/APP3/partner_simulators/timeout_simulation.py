#!/usr/bin/env python3
import time

print("Simulating EMR timeout", flush=True)
time.sleep(6)
raise SystemExit(1)
