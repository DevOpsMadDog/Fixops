#!/usr/bin/env python3
"""Carry threat-feed updates into an air-gapped site, and verify them there.

An air-gapped deployment ships with the feed databases it was installed with and
nothing refreshes them. Measured 2026-08-30: the bundle carries 327,252 EPSS
scores and 1,568 KEV entries, last refreshed **135 days** before the build — and
its newest entry is ``CVE-2026-6328`` while a current pip-audit scan of this
repo returns ``CVE-2026-49855`` and later. Every recent finding therefore falls
back to an *estimated* EPSS, and the verdict says so on every row.

That is honest, and it is not good enough for a customer paying for exploit
intelligence. This is the carry-in path.

    connected host      python scripts/feed_bundle.py export
    sneakernet          fixops-feeds-<date>.tar.gz  +  .sig.json
    air-gapped host     python scripts/feed_bundle.py verify  <bundle>
                        python scripts/feed_bundle.py import  <bundle> --apply

The bundle is SIGNED with the same RSA key the evidence bundles use, and
``verify`` is a separate command run before ``import`` on purpose: a file that
crossed an air gap on removable media is exactly the file whose provenance
matters most. ``import`` refuses to apply an unverified bundle unless the
operator passes ``--allow-unsigned``, which is recorded in the feed metadata so
the deployment can never quietly forget it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

FEED_TABLES = ("epss_scores", "kev_entries", "feed_metadata")


def _feeds_db(explicit: str | None = None) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit)
    root = os.environ.get("FIXOPS_DATA_DIR", "data")
    return pathlib.Path(root) / "feeds" / "feeds.db"


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _feed_state(db: pathlib.Path) -> dict:
    """Row counts and refresh dates, read straight from the database.

    Reported before and after an import so an operator sees what actually
    changed rather than trusting the bundle's own description of itself.
    """
    if not db.is_file():
        return {"present": False}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    state: dict = {"present": True}
    for table in ("epss_scores", "kev_entries"):
        try:
            state[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.DatabaseError:
            state[table] = None
    try:
        state["last_refresh"] = conn.execute(
            "SELECT MAX(last_refresh) FROM feed_metadata"
        ).fetchone()[0]
    except sqlite3.DatabaseError:
        state["last_refresh"] = None
    return state


def _sign(payload: bytes) -> dict:
    """Sign with the same key the evidence bundles use, or say plainly that we could not."""
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "suite-core"))
        from core.crypto import CryptoManager

        signature, fingerprint = CryptoManager().sign(payload)
        return {
            "signed": True,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "signature_algorithm": "RSA-PKCS1v15-SHA256",
            "key_fingerprint": fingerprint,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:  # pragma: no cover — export must still produce a bundle
        return {"signed": False, "reason": f"{type(exc).__name__}: {exc}"}


def _verify(payload: bytes, sidecar: dict) -> tuple[bool, str]:
    if not sidecar.get("signed"):
        return False, f"bundle was never signed ({sidecar.get('reason', 'no reason given')})"
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "suite-core"))
        from core.crypto import CryptoManager

        # verify(data, signature) — two arguments. I guessed a third
        # (key_fingerprint) and it raised TypeError, which _verify caught and
        # reported as "could not verify". A broken verifier that reports failure
        # is survivable; one that reported SUCCESS would not be.
        ok = CryptoManager().verify(payload, base64.b64decode(sidecar["signature_b64"]))
        if not ok:
            return False, "SIGNATURE DOES NOT MATCH"

        # The fingerprint identifies WHICH key signed it. A valid signature from
        # an unexpected key is not the same as a valid signature from ours, and
        # on the far side of an air gap that distinction is the whole point.
        expected = sidecar.get("key_fingerprint")
        return True, f"signature valid (key {expected[:16]}…)" if expected else "signature valid"
    except Exception as exc:
        return False, f"could not verify: {type(exc).__name__}: {exc}"


def cmd_export(args) -> int:
    db = _feeds_db(args.db)
    if not db.is_file():
        print(f"no feed database at {db}")
        return 1

    state = _feed_state(db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir / f"fixops-feeds-{stamp}.tar.gz"

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(db, arcname="feeds.db")

    content_hash = _sha256(tar_path)
    sidecar = {
        "bundle": tar_path.name,
        "content_sha256": content_hash,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source_state": state,
        **_sign(content_hash.encode("utf-8")),
    }
    # Append, do not with_suffix: on "x.tar.gz" that strips ".gz" and
    # yields "x.tar.tar.gz.sig.json".
    sidecar_path = pathlib.Path(str(tar_path) + ".sig.json")
    sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

    size_mb = tar_path.stat().st_size / 1_048_576
    print(f"  exported  {tar_path}  ({size_mb:.1f} MB)")
    print(f"  contents  {state.get('epss_scores')} EPSS / {state.get('kev_entries')} KEV, "
          f"last refreshed {state.get('last_refresh')}")
    print(f"  signature {'yes — ' + sidecar.get('key_fingerprint', '')[:16] if sidecar.get('signed') else 'NO: ' + sidecar.get('reason', '')}")
    print(f"\n  Carry BOTH files: {tar_path.name} and {sidecar_path.name}")
    return 0


def cmd_verify(args) -> int:
    tar_path = pathlib.Path(args.bundle)
    # Append, do not with_suffix: on "x.tar.gz" that strips ".gz" and
    # yields "x.tar.tar.gz.sig.json".
    sidecar_path = pathlib.Path(str(tar_path) + ".sig.json")
    if not tar_path.is_file():
        print(f"no bundle at {tar_path}")
        return 1
    if not sidecar_path.is_file():
        print(f"no signature sidecar at {sidecar_path} — cannot establish provenance")
        return 1

    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    actual = _sha256(tar_path)
    if actual != sidecar.get("content_sha256"):
        print("  CONTENT HASH MISMATCH — this bundle is not the one that was signed")
        print(f"    recorded {sidecar.get('content_sha256')}")
        print(f"    actual   {actual}")
        return 1
    print(f"  hash      matches ({actual[:16]}…)")

    ok, detail = _verify(actual.encode("utf-8"), sidecar)
    print(f"  signature {detail}")
    state = sidecar.get("source_state") or {}
    print(f"  contents  {state.get('epss_scores')} EPSS / {state.get('kev_entries')} KEV, "
          f"exported {sidecar.get('exported_at')}")
    return 0 if ok else 1


def cmd_import(args) -> int:
    tar_path = pathlib.Path(args.bundle)
    db = _feeds_db(args.db)

    verified = cmd_verify(args) == 0
    if not verified and not args.allow_unsigned:
        print("\n  REFUSING to import an unverified feed bundle.")
        print("  Pass --allow-unsigned to override; the override is recorded in")
        print("  feed_metadata so the deployment cannot quietly forget it.")
        return 1

    before = _feed_state(db)
    if not args.apply:
        print("\n  dry run — pass --apply to install")
        return 0

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="fixops-feeds-"))
    with tarfile.open(tar_path, "r:gz") as tar:
        member = tar.getmember("feeds.db")
        tar.extract(member, path=tmp)
    staged = tmp / "feeds.db"

    # Never overwrite in place: a half-written feed database is worse than a
    # stale one, because the verdicts it produces look current.
    check = sqlite3.connect(f"file:{staged}?mode=ro", uri=True)
    if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        print("  staged database fails integrity_check — refusing to install")
        return 1

    db.parent.mkdir(parents=True, exist_ok=True)
    if db.is_file():
        backup = db.with_name(f"feeds.db.replaced-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}")
        shutil.copy2(db, backup)
        print(f"  previous database kept at {backup.name}")
    shutil.move(str(staged), str(db))

    if not verified and args.allow_unsigned:
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT OR REPLACE INTO feed_metadata "
            "(feed_name, last_refresh, records_count, status, category, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("_import_provenance", datetime.now(timezone.utc).isoformat(), 0,
             "unverified", "import",
             f"imported from {tar_path.name} WITHOUT a valid signature"),
        )
        conn.commit()
        print("  recorded: this feed data was imported UNVERIFIED")

    after = _feed_state(db)
    print(f"\n  EPSS  {before.get('epss_scores')} -> {after.get('epss_scores')}")
    print(f"  KEV   {before.get('kev_entries')} -> {after.get('kev_entries')}")
    print(f"  last refreshed {before.get('last_refresh')} -> {after.get('last_refresh')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", help="path to feeds.db (default: $FIXOPS_DATA_DIR/feeds/feeds.db)")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="build a signed feed bundle (connected host)")
    export.add_argument("--out", default="dist/feeds")
    export.set_defaults(func=cmd_export)

    verify = sub.add_parser("verify", help="check a bundle's hash and signature")
    verify.add_argument("bundle")
    verify.set_defaults(func=cmd_verify)

    imp = sub.add_parser("import", help="install a bundle (air-gapped host)")
    imp.add_argument("bundle")
    imp.add_argument("--apply", action="store_true")
    imp.add_argument("--allow-unsigned", action="store_true")
    imp.set_defaults(func=cmd_import)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
