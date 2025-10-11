#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sign-artifact.sh --artifact <path> --key <key-path> [--signature <sig-path>] [--predicate <predicate-json>] [--attestation-out <dsse-path>] [--bundle-out <bundle-path>]

Required arguments:
  --artifact         Path to the release artifact to sign (tarball, image archive, etc.).
  --key              Path to the Cosign private key file used for signing. You can also
                     supply COSIGN_KEY_PATH in the environment instead of this flag.

Optional arguments:
  --signature        Destination file for the Cosign blob signature (defaults to <artifact>.sig).
  --predicate        Path to a predicate payload (for example a SLSA provenance JSON) to wrap in a DSSE attestation.
  --attestation-out  Destination path for the DSSE envelope generated via cosign attest-blob. Required when --predicate is set.
  --bundle-out       Optional bundle output written by cosign attest-blob when --predicate is supplied.

Environment variables:
  COSIGN_PASSWORD    Password protecting the private key. Required when the key is password protected.
  COSIGN_KEY_PATH    Alternative way to supply the signing key path instead of --key.

This helper wraps cosign sign-blob for FixOps release assets. When a predicate is provided
an additional DSSE envelope is created with cosign attest-blob so downstream consumers can
verify provenance alongside detached signatures.
USAGE
}

ARTIFACT=""
KEY_FILE="${COSIGN_KEY_PATH:-}"
SIGNATURE=""
PREDICATE=""
ATTESTATION_OUT=""
BUNDLE_OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --key)
      KEY_FILE="$2"
      shift 2
      ;;
    --signature)
      SIGNATURE="$2"
      shift 2
      ;;
    --predicate)
      PREDICATE="$2"
      shift 2
      ;;
    --attestation-out)
      ATTESTATION_OUT="$2"
      shift 2
      ;;
    --bundle-out)
      BUNDLE_OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ARTIFACT" ]]; then
  echo "--artifact is required" >&2
  usage >&2
  exit 1
fi

if [[ -z "$KEY_FILE" ]]; then
  echo "--key or COSIGN_KEY_PATH is required" >&2
  usage >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "Artifact '$ARTIFACT' not found" >&2
  exit 1
fi

if [[ ! -f "$KEY_FILE" ]]; then
  echo "Key '$KEY_FILE' not found" >&2
  exit 1
fi

SIGNATURE="${SIGNATURE:-${ARTIFACT}.sig}"

cosign sign-blob \
  --key "$KEY_FILE" \
  --output-signature "$SIGNATURE" \
  "$ARTIFACT"

echo "Wrote signature to $SIGNATURE" >&2

if [[ -n "$PREDICATE" ]]; then
  if [[ ! -f "$PREDICATE" ]]; then
    echo "Predicate '$PREDICATE' not found" >&2
    exit 1
  fi
  if [[ -z "$ATTESTATION_OUT" ]]; then
    echo "--attestation-out must be supplied when --predicate is set" >&2
    exit 1
  fi
  cmd=(
    cosign attest-blob
    --key "$KEY_FILE"
    --predicate "$PREDICATE"
    --type slsaprovenance
    --yes
    --output-attestation "$ATTESTATION_OUT"
    "$ARTIFACT"
  )
  if [[ -n "$BUNDLE_OUT" ]]; then
    cmd+=(--bundle "$BUNDLE_OUT")
  fi
  "${cmd[@]}"
  echo "Wrote DSSE attestation to $ATTESTATION_OUT" >&2
  if [[ -n "$BUNDLE_OUT" ]]; then
    echo "Wrote verification bundle to $BUNDLE_OUT" >&2
  fi
fi
