# PRD — Community 549: ZeroGravity Compressor — Auto-Detect Decompress

## Master Goal Mapping
**ALDECI Pillar:** ZeroGravity ML context layer — decompresses blobs by reading the 3-byte magic header to select algorithm, with raw-zlib fallback for legacy data.

## Architecture Diagram
```mermaid
graph LR
    A[compressed bytes] --> B[decompress]
    B -->|magic[:3]| C{ZG01/ZG02/ZG03/unknown}
    C -->|ZG01| D[zlib.decompress data[3:]]
    C -->|ZG02| E[gzip.decompress data[3:]]
    C -->|ZG03| F[bz2.decompress data[3:]]
    C -->|fallback| G[try zlib or return raw]
```

## Code Proof
**File:** `suite-core/core/zero_gravity.py:L145`  
**Module:** `zero_gravity.Compressor.decompress`

```python
@staticmethod
def decompress(data: bytes) -> bytes:
    """Decompress data with auto-detected algorithm."""
    if data[:3] == Compressor.MAGIC["zlib"]:
        return zlib.decompress(data[3:])
    elif data[:3] == Compressor.MAGIC["gzip"]:
        return gzip.decompress(data[3:])
    elif data[:3] == Compressor.MAGIC["bz2"]:
        import bz2; return bz2.decompress(data[3:])
    else:
        try: return zlib.decompress(data)
        except zlib.error: return data
```

## Inter-Dependencies
- `Compressor.compress()` — C548, produces magic-prefixed blobs
- `Compressor.ratio()` — C550, used before/after compress cycle
- ZeroGravity context store — calls decompress on retrieval

## Data Flow
Compressed blob → header inspection → algorithm dispatch → stdlib decompress → raw bytes returned.

## Referenced Docs
- ALDECI Rearchitecture v2 §Context Compression
- Python zlib error handling docs

## Acceptance Criteria
- [ ] ZG\x01 prefix → zlib decompress
- [ ] ZG\x02 prefix → gzip decompress
- [ ] ZG\x03 prefix → bz2 decompress
- [ ] Unknown prefix → try raw zlib, else return data unchanged
- [ ] Round-trip fidelity for all three algorithms

## Effort Estimate
S — 1 day (implemented; add fallback tests)

## Status
DONE — implemented at L145
