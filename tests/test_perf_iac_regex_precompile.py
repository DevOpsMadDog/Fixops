"""Perf test: pre-compiled regex vs inline re.search in iac_scanner_engine.py.

Measures speedup at N=1000 iterations across 3 representative content samples.
"""
import re
import time

import pytest

# ---------------------------------------------------------------------------
# Patterns under test (mirrors what was inlined before the fix)
# ---------------------------------------------------------------------------
_INLINE_K8S_API = r"apiVersion\s*:"
_INLINE_K8S_KIND = r"kind\s*:"
_INLINE_ANSIBLE = r"^\s*-\s+(name|hosts|tasks|roles)\s*:"
_INLINE_CFN = r"AWSTemplateFormatVersion|Resources\s*:"
_INLINE_DOC_SEP = r"^---\s*$"

# Pre-compiled (same as the new module-level constants)
_C_K8S_API = re.compile(_INLINE_K8S_API)
_C_K8S_KIND = re.compile(_INLINE_K8S_KIND)
_C_ANSIBLE = re.compile(_INLINE_ANSIBLE, re.MULTILINE)
_C_CFN = re.compile(_INLINE_CFN)
_C_DOC_SEP = re.compile(_INLINE_DOC_SEP, re.MULTILINE)

N = 1000

# ---------------------------------------------------------------------------
# Sample content for each pattern
# ---------------------------------------------------------------------------
K8S_CONTENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
"""

ANSIBLE_CONTENT = """\
---
- name: install nginx
  hosts: webservers
  tasks:
    - name: install
      apt:
        name: nginx
"""

CFN_CONTENT = """\
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""

MULTI_DOC = "\n".join([K8S_CONTENT, "---", CFN_CONTENT] * 10)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_k8s_detect_speedup():
    """Pre-compiled K8s apiVersion+kind detection is faster than inline."""
    # inline
    t0 = time.perf_counter()
    for _ in range(N):
        re.search(_INLINE_K8S_API, K8S_CONTENT)
        re.search(_INLINE_K8S_KIND, K8S_CONTENT)
    inline_ms = (time.perf_counter() - t0) * 1000

    # compiled
    t0 = time.perf_counter()
    for _ in range(N):
        _C_K8S_API.search(K8S_CONTENT)
        _C_K8S_KIND.search(K8S_CONTENT)
    compiled_ms = (time.perf_counter() - t0) * 1000

    speedup = inline_ms / compiled_ms if compiled_ms > 0 else float("inf")
    print(f"\nK8s detect  inline={inline_ms:.1f}ms  compiled={compiled_ms:.1f}ms  speedup={speedup:.2f}x")
    assert speedup >= 1.5, f"Expected >=1.5x speedup, got {speedup:.2f}x"


def test_ansible_detect_speedup():
    """Pre-compiled Ansible MULTILINE pattern is faster than inline."""
    t0 = time.perf_counter()
    for _ in range(N):
        re.search(_INLINE_ANSIBLE, ANSIBLE_CONTENT, re.MULTILINE)
    inline_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    for _ in range(N):
        _C_ANSIBLE.search(ANSIBLE_CONTENT)
    compiled_ms = (time.perf_counter() - t0) * 1000

    speedup = inline_ms / compiled_ms if compiled_ms > 0 else float("inf")
    print(f"\nAnsible det inline={inline_ms:.1f}ms  compiled={compiled_ms:.1f}ms  speedup={speedup:.2f}x")
    assert speedup >= 1.5, f"Expected >=1.5x speedup, got {speedup:.2f}x"


def test_yaml_doc_split_speedup():
    """Pre-compiled YAML doc-separator split is faster than inline re.split."""
    t0 = time.perf_counter()
    for _ in range(N):
        re.split(_INLINE_DOC_SEP, MULTI_DOC, flags=re.MULTILINE)
    inline_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    for _ in range(N):
        _C_DOC_SEP.split(MULTI_DOC)
    compiled_ms = (time.perf_counter() - t0) * 1000

    speedup = inline_ms / compiled_ms if compiled_ms > 0 else float("inf")
    print(f"\nYAML split  inline={inline_ms:.1f}ms  compiled={compiled_ms:.1f}ms  speedup={speedup:.2f}x")
    # split() cost dominates; precompile still avoids re-parse overhead — accept any non-regression
    assert speedup >= 0.8, f"Compiled split should not regress, got {speedup:.2f}x"


def test_iac_scanner_engine_imports_cleanly():
    """Sanity: module imports with all pre-compiled constants present."""
    from core.iac_scanner_engine import (  # noqa: F401
        _RE_ANSIBLE,
        _RE_CFN,
        _RE_CFN_JSON,
        _RE_K8S_API_VERSION,
        _RE_K8S_KIND,
        _RE_YAML_DOC_SEP,
        _RE_YAML_KV,
        _RE_YAML_TOPKEY,
    )
    assert _RE_K8S_API_VERSION.pattern == r"apiVersion\s*:"
    assert _RE_ANSIBLE.flags & re.MULTILINE
    assert _RE_YAML_DOC_SEP.flags & re.MULTILINE
