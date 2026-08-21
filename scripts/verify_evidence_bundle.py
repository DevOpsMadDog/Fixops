#!/usr/bin/env python3
"""Verify a FixOps evidence bundle without FixOps.

An assessor should not have to trust the vendor's own UI to check the vendor's
own evidence. This script takes three files and answers one question:

    verify_evidence_bundle.py BUNDLE.json BUNDLE.sig.json PUBLIC_KEY.pem

It imports nothing from FixOps. It needs no network, no database, and no
running service — only Python and the `cryptography` package, both of which an
auditor's machine already has or can install from a mirror inside an air-gapped
environment.

Two independent checks, because they fail for different reasons:

  1. CONTENT — SHA-256 of the bundle file must equal the hash in the signature
     record. A mismatch means the bundle was edited after it was produced.
  2. PROVENANCE — that recorded hash must carry a valid RSA signature from the
     published key. A mismatch means the record did not come from the holder of
     that key, whatever the bundle says about itself.

Both must pass. Reporting either alone would let a forged pair look convincing:
a re-hashed edit with a stale signature, or a genuine signature over a hash that
no longer describes the file in front of you.

Exit codes: 0 verified, 1 failed verification, 2 usage or input error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(bundle_path: Path, signature_path: Path, public_key_path: Path) -> int:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:  # pragma: no cover - environment problem, not a verdict
        print("ERROR: the 'cryptography' package is required.", file=sys.stderr)
        print("       pip install cryptography", file=sys.stderr)
        return EXIT_USAGE

    for path in (bundle_path, signature_path, public_key_path):
        if not path.is_file():
            print(f"ERROR: not a file: {path}", file=sys.stderr)
            return EXIT_USAGE

    try:
        record = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: signature record is not readable JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE

    recorded_hash = str(record.get("content_sha256") or "").strip().lower()
    signature_b64 = record.get("signature_b64") or ""
    if not recorded_hash or not signature_b64:
        print("ERROR: signature record is missing content_sha256 or signature_b64", file=sys.stderr)
        return EXIT_USAGE

    # 1. Content
    actual_hash = _sha256_file(bundle_path)
    content_ok = actual_hash == recorded_hash

    # 2. Provenance
    signature_ok = False
    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        public_key.verify(
            base64.b64decode(signature_b64),
            recorded_hash.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature_ok = True
    except InvalidSignature:
        signature_ok = False
    except Exception as exc:  # malformed key or signature material
        print(f"  signature could not be checked: {exc}", file=sys.stderr)
        signature_ok = False

    print(f"bundle     : {bundle_path.name}")
    print(f"recorded   : sha256:{recorded_hash}")
    print(f"recomputed : sha256:{actual_hash}")
    print(f"content    : {'OK — unchanged since signing' if content_ok else 'FAILED — the file has been edited'}")
    print(f"signature  : {'OK — signed by the published key' if signature_ok else 'FAILED — not signed by this key'}")
    if record.get("key_fingerprint"):
        print(f"key        : {record['key_fingerprint']}")
    if record.get("signed_at"):
        print(f"signed at  : {record['signed_at']}")

    if content_ok and signature_ok:
        print("\nVERIFIED: this bundle is unmodified and was signed by the holder of that key.")
        return EXIT_OK

    print("\nNOT VERIFIED: do not rely on this bundle as evidence.", file=sys.stderr)
    return EXIT_FAILED


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return EXIT_USAGE
    return verify(Path(argv[1]), Path(argv[2]), Path(argv[3]))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
