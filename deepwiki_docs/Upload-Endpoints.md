# Upload Endpoints

> **Relevant source files**
> * [apps/api/app.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py)
> * [apps/api/ingestion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/ingestion.py)
> * [config/normalizers/registry.yaml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/normalizers/registry.yaml)
> * [core/cli.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/cli.py)
> * [core/micro_pentest.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/micro_pentest.py)
> * [data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/0.part](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/0.part)
> * [data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/meta.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/meta.json)
> * [data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/sample.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/uploads/6c94680a-4934-447c-91bf-22ac1356a9e7/sample.json)
> * [data/uploads/upload_1759388274014/metadata.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/uploads/upload_1759388274014/metadata.json)
> * [data/uploads/upload_1759388360124/metadata.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/data/uploads/upload_1759388360124/metadata.json)
> * [tests/test_enterprise_services.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enterprise_services.py)
> * [tests/test_http_metrics.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_http_metrics.py)
> * [tests/test_ingestion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_ingestion.py)
> * [tests/test_micro_pentest_cli.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_micro_pentest_cli.py)
> * [tests/test_micro_pentest_core.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_micro_pentest_core.py)
> * [tests/test_micro_pentest_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_micro_pentest_router.py)

## Purpose and Scope

This document describes the upload endpoints in the FixOps Data Ingestion Layer that accept security artifacts from external sources. These endpoints handle file uploads for SBOM, SARIF, CVE feeds, VEX documents, CNAPP findings, design context, and business context. The upload system supports both direct single-file uploads and chunked multi-part uploads for large files.

For information about input normalization and format parsing, see [Input Normalization](/DevOpsMadDog/Fixops/3.4-input-normalization). For chunked upload management details, see [Chunked Upload System](/DevOpsMadDog/Fixops/3.3-chunked-upload-system). For pipeline orchestration after ingestion, see [Pipeline Orchestrator](/DevOpsMadDog/Fixops/6.2-pipeline-orchestrator).

---

## Upload Endpoint Architecture

The upload endpoints are defined in the FastAPI application and follow a consistent pattern for ingesting different artifact types. Each endpoint accepts file uploads, validates them against size limits, normalizes the content, and stores both the normalized data and raw bytes for archival.

### Endpoint Structure

```mermaid
flowchart TD

Client["External Client<br>CLI, CI/CD, Web UI"]
Router["FastAPI Router<br>create_app"]
Auth["API Key/JWT Auth<br>_verify_api_key"]
DesignEP["/api/v1/inputs/design"]
SBOMEP["/api/v1/inputs/sbom"]
SARIFEP["/api/v1/inputs/sarif"]
CVEEP["/api/v1/inputs/cve"]
VEXEP["/api/v1/inputs/vex"]
CNAPPEP["/api/v1/inputs/cnapp"]
ContextEP["/api/v1/inputs/context"]
ChunkedEP["/api/v1/scans/upload"]
ReadLimited["_read_limited<br>Stream upload with size limit"]
Validate["_validate_content_type<br>Content-Type validation"]
ProcessDesign["_process_design"]
ProcessSBOM["_process_sbom"]
ProcessSARIF["_process_sarif"]
ProcessCVE["_process_cve"]
ProcessVEX["_process_vex"]
ProcessCNAPP["_process_cnapp"]
ProcessContext["_process_context"]
Store["_store<br>Persist to artifacts dict"]
Archive["ArtefactArchive<br>archive.persist"]
StateArtifacts["app.state.artifacts<br>In-memory dict"]
ArchiveRecords["app.state.archive_records<br>Persistence metadata"]
ArchiveDir["Archive Directory<br>.fixops_data/archive"]

Client -.-> Router
Store -.-> StateArtifacts
Archive -.-> ArchiveDir
Archive -.-> ArchiveRecords

subgraph Storage ["Storage"]
    StateArtifacts
    ArchiveRecords
    ArchiveDir
end

subgraph subGraph2 ["FastAPI Application"]
    Router
    Auth
    ReadLimited
    Validate
    Store
    Archive
    Router -.-> Auth
    Auth -.-> DesignEP
    Auth -.-> SBOMEP
    Auth -.-> SARIFEP
    Auth -.-> CVEEP
    Auth -.-> VEXEP
    Auth -.-> CNAPPEP
    Auth -.-> ContextEP
    Auth -.-> ChunkedEP
    DesignEP -.-> ReadLimited
    SBOMEP -.-> ReadLimited
    SARIFEP -.-> ReadLimited
    CVEEP -.-> ReadLimited
    VEXEP -.-> ReadLimited
    CNAPPEP -.-> ReadLimited
    ContextEP -.-> ReadLimited
    ReadLimited -.-> Validate
    Validate -.-> ProcessDesign
    Validate -.-> ProcessSBOM
    Validate -.-> ProcessSARIF
    Validate -.-> ProcessCVE
    Validate -.-> ProcessVEX
    Validate -.-> ProcessCNAPP
    Validate -.-> ProcessContext
    ProcessDesign -.-> Store
    ProcessSBOM -.-> Store
    ProcessSARIF -.-> Store
    ProcessCVE -.-> Store
    ProcessVEX -.-> Store
    ProcessCNAPP -.-> Store
    ProcessContext -.-> Store
    Store -.-> Archive

subgraph subGraph1 ["Processing Functions"]
    ProcessDesign
    ProcessSBOM
    ProcessSARIF
    ProcessCVE
    ProcessVEX
    ProcessCNAPP
    ProcessContext
end

subgraph subGraph0 ["Upload Endpoints"]
    DesignEP
    SBOMEP
    SARIFEP
    CVEEP
    VEXEP
    CNAPPEP
    ContextEP
    ChunkedEP
end
end
```

**Sources:** [apps/api/app.py L266-L1027](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L266-L1027)

---

## Format-Specific Endpoints

### Design CSV Endpoint

**Endpoint:** `POST /api/v1/inputs/design`

Accepts CSV files containing design context with component metadata. The endpoint parses CSV rows and validates required columns in strict mode.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | CSV file with component design information |
| Content-Type | string | No | `text/csv` or `application/csv` |

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["CSV Upload"]
ReadBuffer["_read_limited<br>SpooledTemporaryFile"]
Wrapper["TextIOWrapper<br>UTF-8 decode"]
CSVReader["csv.DictReader<br>Parse rows"]
Validate["Validate Required Columns<br>if strict_validation=True"]
Store["_store('design')<br>columns + rows dict"]
Response["200 OK<br>row_count, columns"]

Upload -.-> ReadBuffer
ReadBuffer -.-> Wrapper
Wrapper -.-> CSVReader
CSVReader -.-> Validate
Validate -.-> Store
Store -.-> Response
```

**Required Columns (strict mode):**

* `component`
* `subcomponent`
* `owner`
* `data_class`
* `description`
* `control_scope`

**Sources:** [apps/api/app.py L687-L739](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L687-L739)

---

### SBOM Endpoint

**Endpoint:** `POST /api/v1/inputs/sbom`

Accepts SBOM files in CycloneDX, SPDX, or GitHub dependency snapshot formats. Uses `InputNormalizer.load_sbom()` with fallback parsers for format detection.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | JSON SBOM file |
| Content-Type | string | No | `application/json` |

**Supported Formats:**

* CycloneDX 1.4, 1.5, 1.6
* SPDX 2.2, 2.3
* GitHub dependency snapshot
* Syft JSON output

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["SBOM JSON"]
ReadBuffer["Read to Buffer"]
ParseJSON["json.load<br>Parse JSON"]
DetectFormat["Detect bomFormat<br>CycloneDX/SPDX/GitHub/Syft"]
Normalizer["InputNormalizer.load_sbom<br>3 fallback parsers"]
ValidateStrict["Validate Format<br>if strict_validation=True"]
Store["_store('sbom')<br>NormalizedSBOM"]
Response["200 OK<br>format, component_preview"]

Upload -.-> ReadBuffer
ReadBuffer -.-> ParseJSON
ParseJSON -.-> DetectFormat
DetectFormat -.-> Normalizer
Normalizer -.-> ValidateStrict
ValidateStrict -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L741-L812](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L741-L812)

---

### SARIF Endpoint

**Endpoint:** `POST /api/v1/inputs/sarif`

Accepts SARIF 2.1.0 static analysis results from tools like Semgrep, Snyk, GitLab SAST, and Trivy.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | SARIF JSON file |
| Content-Type | string | No | `application/json` |

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["SARIF JSON"]
Normalizer["InputNormalizer.load_sarif<br>Parse runs + results"]
Extract["Extract Findings<br>rules, locations, severities"]
Store["_store('sarif')<br>NormalizedSARIF"]
Response["200 OK<br>tools, metadata"]

Upload -.-> Normalizer
Normalizer -.-> Extract
Extract -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L894-L912](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L894-L912)

---

### CVE Feed Endpoint

**Endpoint:** `POST /api/v1/inputs/cve`

Accepts CVE feed data in NVD JSON or CVE JSON 5.1 formats.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | CVE JSON file |
| Content-Type | string | No | `application/json` |

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["CVE JSON"]
Normalizer["InputNormalizer.load_cve_feed"]
Validate["Validate Records<br>Check required fields"]
StrictCheck["if strict_validation<br>Reject if errors"]
Store["_store('cve')<br>NormalizedCVEFeed"]
Response["200 OK<br>record_count, validation_errors"]

Upload -.-> Normalizer
Normalizer -.-> Validate
Validate -.-> StrictCheck
StrictCheck -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L814-L848](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L814-L848)

---

### VEX Endpoint

**Endpoint:** `POST /api/v1/inputs/vex`

Accepts VEX (Vulnerability Exploitability eXchange) documents for noise reduction by suppressing known false positives.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | VEX JSON file |
| Content-Type | string | No | `application/json` |

**Supported Formats:**

* CycloneDX VEX
* CSAF VEX
* OpenVEX

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["VEX JSON"]
Normalizer["InputNormalizer.load_vex"]
Extract["Extract Suppressed Refs<br>not_affected assertions"]
Store["_store('vex')<br>NormalizedVEX"]
Response["200 OK<br>assertions, not_affected count"]

Upload -.-> Normalizer
Normalizer -.-> Extract
Extract -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L850-L868](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L850-L868)

---

### CNAPP Endpoint

**Endpoint:** `POST /api/v1/inputs/cnapp`

Accepts Cloud-Native Application Protection Platform findings from tools like Wiz, Prisma Cloud, Aqua, and Orca.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | CNAPP findings JSON |
| Content-Type | string | No | `application/json` |

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["CNAPP JSON"]
Normalizer["InputNormalizer.load_cnapp"]
Extract["Extract Assets + Findings<br>cloud resources"]
Store["_store('cnapp')<br>NormalizedCNAPP"]
Response["200 OK<br>asset_count, finding_count"]

Upload -.-> Normalizer
Normalizer -.-> Extract
Extract -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L870-L892](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L870-L892)

---

### Business Context Endpoint

**Endpoint:** `POST /api/v1/inputs/context`

Accepts business context in FixOps.yaml, OTM.json, or SSVC YAML formats to enrich vulnerability decisions with SSVC factors.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | UploadFile | Yes | Context file (YAML or JSON) |
| Content-Type | string | No | Detected from extension |

**Supported Formats:**

* FixOps.yaml (custom format)
* OTM.json (Open Threat Model)
* SSVC YAML (CISA SSVC decision points)

**Processing Pipeline:**

```mermaid
flowchart TD

Upload["Context File"]
Normalizer["InputNormalizer.load_business_context"]
DetectFormat["Auto-detect Format<br>YAML/JSON"]
ExtractSSVC["Extract SSVC Factors<br>exploitation, exposure, etc."]
Store["_store('context')<br>NormalizedBusinessContext"]
Response["200 OK<br>format, ssvc_factors, components"]

Upload -.-> Normalizer
Normalizer -.-> DetectFormat
DetectFormat -.-> ExtractSSVC
ExtractSSVC -.-> Store
Store -.-> Response
```

**Sources:** [apps/api/app.py L914-L938](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L914-L938)

---

## Upload Size Limits and Validation

### Size Limit Configuration

Each upload stage has configurable size limits defined in the overlay configuration:

| Stage | Default Limit | Configuration Key |
| --- | --- | --- |
| design | 8 MB | `upload_limits.design` |
| sbom | 8 MB | `upload_limits.sbom` |
| sarif | 8 MB | `upload_limits.sarif` |
| cve | 8 MB | `upload_limits.cve` |
| vex | 8 MB | `upload_limits.vex` |
| cnapp | 8 MB | `upload_limits.cnapp` |
| context | 8 MB | `upload_limits.context` |

### Upload Streaming

The `_read_limited()` function implements chunked streaming to prevent memory exhaustion:

```

```

**Configuration:**

* `_CHUNK_SIZE = 1024 * 1024` (1 MB)
* `_RAW_BYTES_THRESHOLD = 4 * 1024 * 1024` (4 MB for in-memory storage)

**Sources:** [apps/api/app.py L593-L642](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L593-L642)

---

### Content Type Validation

The `_validate_content_type()` function enforces expected MIME types:

**Validation Rules:**

| Stage | Expected Content Types |
| --- | --- |
| design | `text/csv`, `application/csv` |
| sbom | `application/json` |
| sarif | `application/json` |
| cve | `application/json` |
| vex | `application/json` |
| cnapp | `application/json` |
| context | `application/json`, `application/x-yaml`, `text/yaml` |

**Error Response:**

```json
{
  "message": "Unsupported content type",
  "received": "text/plain",
  "expected": ["application/json"]
}
```

**Sources:** [apps/api/app.py L643-L652](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L643-L652)

---

## Chunked Upload System

For large files exceeding single request limits, the system provides chunked upload support via `ChunkUploadManager`.

### Chunked Upload Flow

```mermaid
sequenceDiagram
  participant p1 as Client
  participant p2 as POST /api/v1/scans/upload
  participant p3 as ChunkUploadManager
  participant p4 as uploads_dir

  p1->>p2: Initiate Upload (file_name, total_size)
  p2->>p3: start_upload(file_name, total_size, metadata)
  p3->>p4: Create upload_id directory
  p3->>p4: Write metadata.json
  p3-->>p2: upload_id
  p2-->>p1: 200 OK {upload_id, chunk_size: 1MB}
  loop For each chunk
    p1->>p2: Upload Chunk (upload_id, chunk_index, data)
    p2->>p3: receive_chunk(upload_id, chunk_index, data)
    p3->>p4: Write chunk_index.part
    p3->>p4: Update metadata.json (chunks_received)
    p3-->>p2: chunk_received, total_chunks
    p2-->>p1: 200 OK {chunks_received, complete: false}
  end
  p1->>p2: Complete Upload (upload_id)
  p2->>p3: complete_upload(upload_id)
  p3->>p4: Combine chunk files
  p3->>p4: Write final file
  p3->>p4: Delete chunk files
  p3-->>p2: final_path
  p2-->>p1: 200 OK {status: complete, file_path}
```

### Chunked Upload Endpoints

**Initiate Upload:**

```
POST /api/v1/scans/upload
{
  "file_name": "large-sbom.json",
  "total_size": 52428800,
  "scan_type": "sbom",
  "service_name": "api-gateway",
  "environment": "production"
}
```

**Upload Chunk:**

```
POST /api/v1/scans/upload/{upload_id}/chunk
Content-Type: application/octet-stream
X-Chunk-Index: 0

<binary data>
```

**Complete Upload:**

```
POST /api/v1/scans/upload/{upload_id}/complete
```

**Sources:** [apps/api/app.py L461-L467](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L461-L467)

---

## Input Validation and Security

### Path Security

All upload paths go through `safe_path_ops` validation to prevent path traversal attacks:

```mermaid
flowchart TD

UploadRequest["Upload Request"]
ExtractFilename["Extract filename"]
Sanitize["safe_path_ops<br>3-stage validation"]
CheckRoot["Inside<br>TRUSTED_ROOT?"]
Reject["HTTPException 400"]
CheckBase["Inside<br>SCAN_BASE_PATH?"]
TempDir["safe_tempdir"]
Process["Process Upload"]

UploadRequest -.-> ExtractFilename
ExtractFilename -.-> Sanitize
Sanitize -.->|"Yes"| CheckRoot
CheckRoot -.->|"No"| Reject
CheckRoot -.->|"Yes"| CheckBase
CheckBase -.->|"No"| Reject
CheckBase -.-> TempDir
TempDir -.-> Process
```

**Trusted Roots:**

* `/var/fixops` (TRUSTED_ROOT)
* `/var/fixops/scans` (SCAN_BASE_PATH)

**Sources:** [apps/api/app.py L174](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L174-L174)

---

### Strict Validation Mode

When `overlay.toggles.strict_validation = True`, additional validation is enforced:

| Stage | Strict Validation Rules |
| --- | --- |
| design | All required CSV columns must be present |
| sbom | `bomFormat` must be "CycloneDX" or "SPDX" |
| cve | All CVE records must pass schema validation |
| sarif | SARIF schema must be valid |

**Sources:** [apps/api/app.py L707-L727](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L707-L727)

 [apps/api/app.py L753-L791](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L753-L791)

 [apps/api/app.py L826-L838](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L826-L838)

---

## Normalization Pipeline

After upload validation, each artifact is passed to `InputNormalizer` for format-specific parsing.

### Normalizer Selection

```mermaid
flowchart TD

Upload["Uploaded File"]
Detect["Format Detection<br>bomFormat, $schema, structure"]
SBOM["SBOM?"]
SARIF["SARIF?"]
CVE["CVE?"]
VEX["VEX?"]
CNAPP["CNAPP?"]
CDXParser["lib4sbom parser"]
SPDXParser["SPDX parser"]
GitHubParser["GitHub snapshot parser"]
SyftParser["Syft JSON parser"]
SARIFParser["SARIF 2.1.0 parser"]
CVEParser["NVD/CVE 5.1 parser"]
VEXParser["CycloneDX/CSAF VEX parser"]
CNAPPParser["Multi-vendor CNAPP parser"]
Normalized["NormalizedSBOM"]
NormalizedSARIF["NormalizedSARIF"]
NormalizedCVEFeed["NormalizedCVEFeed"]
NormalizedVEX["NormalizedVEX"]
NormalizedCNAPP["NormalizedCNAPP"]

Upload -.-> Detect
Detect -.->|"Syft"| SBOM
Detect -.-> SARIF
Detect -.-> CVE
Detect -.-> VEX
Detect -.-> CNAPP
SBOM -.->|"SPDX"| CDXParser
SBOM -.->|"GitHub"| SPDXParser
SBOM -.->|"CycloneDX"| GitHubParser
SBOM -.-> SyftParser
SARIF -.-> SARIFParser
CVE -.-> CVEParser
VEX -.-> VEXParser
CNAPP -.-> CNAPPParser
CDXParser -.-> Normalized
SPDXParser -.-> Normalized
GitHubParser -.-> Normalized
SyftParser -.-> Normalized
SARIFParser -.-> NormalizedSARIF
CVEParser -.-> NormalizedCVEFeed
VEXParser -.-> NormalizedVEX
CNAPPParser -.-> NormalizedCNAPP
```

**Normalized Output Models:**

* `NormalizedSBOM`: Components with purls, versions, licenses
* `NormalizedSARIF`: Results with rules, locations, severities
* `NormalizedCVEFeed`: CVE records with CVSS scores, descriptions
* `NormalizedVEX`: Suppressed vulnerability references
* `NormalizedCNAPP`: Cloud assets and security findings
* `NormalizedBusinessContext`: SSVC factors and component metadata

**Sources:** [apps/api/normalizers.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/normalizers.py)

 (referenced but not in provided files)

---

## Storage and Archival

### Dual Storage Pattern

Each uploaded artifact is stored in two locations:

1. **In-Memory State:** `app.state.artifacts[stage]` - Used by PipelineOrchestrator
2. **Archive Directory:** Persistent storage with raw bytes and metadata

```mermaid
flowchart TD

ProcessedArtifact["Processed Artifact"]
MemoryStore["app.state.artifacts[stage]<br>Normalized object"]
ArchiveCall["archive.persist(stage, payload, raw_bytes)"]
ComputeHash["SHA-256 hash<br>of raw bytes"]
WriteJSON["Write normalized JSON"]
WriteRaw["Write raw bytes<br>(if < 4MB)"]
WriteMetadata["Write metadata.json"]
ArchiveDir["archive_dir////"]
RecordState["app.state.archive_records[stage]"]

ProcessedArtifact -.-> MemoryStore
ProcessedArtifact -.-> ArchiveCall
ArchiveCall -.-> ComputeHash
ArchiveCall -.-> WriteJSON
ArchiveCall -.-> WriteRaw
ArchiveCall -.-> WriteMetadata
WriteJSON -.-> ArchiveDir
WriteRaw -.-> ArchiveDir
WriteMetadata -.-> ArchiveDir
ComputeHash -.-> RecordState
```

### Archive Directory Structure

```
.fixops_data/archive/<mode>/
├── design/
│   └── <hash>/
│       ├── metadata.json
│       ├── normalized.json
│       └── raw.csv
├── sbom/
│   └── <hash>/
│       ├── metadata.json
│       ├── normalized.json
│       └── raw.json
├── sarif/
│   └── <hash>/
│       ├── metadata.json
│       ├── normalized.json
│       └── raw.json
└── cve/
    └── <hash>/
        ├── metadata.json
        ├── normalized.json
        └── raw.json
```

**Metadata Fields:**

* `stage`: Artifact stage (design, sbom, sarif, etc.)
* `timestamp`: ISO 8601 upload timestamp
* `hash`: SHA-256 hash of raw bytes
* `original_filename`: Uploaded filename
* `size_bytes`: Raw file size
* `normalized_path`: Path to normalized JSON
* `raw_path`: Path to raw bytes (if stored)

**Sources:** [apps/api/app.py L654-L675](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L654-L675)

 [core/storage.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/storage.py#LNaN-LNaN)

---

## Error Handling

### HTTP Error Responses

| Status Code | Condition | Response Body |
| --- | --- | --- |
| 400 | Invalid format or missing fields | `{"detail": "Failed to parse SBOM: ..."}` |
| 413 | Upload exceeds size limit | `{"detail": {"message": "Upload exceeded limit", "max_bytes": 8388608, "received_bytes": 9000000}}` |
| 415 | Unsupported content type | `{"detail": {"message": "Unsupported content type", "received": "text/plain", "expected": ["application/json"]}}` |
| 422 | Validation error in strict mode | `{"detail": {"message": "Design CSV missing required columns", "missing_columns": ["owner", "data_class"]}}` |
| 500 | Internal processing error | `{"detail": "Failed to parse CVE feed: ..."}` |

### Error Response Examples

**Upload Too Large:**

```json
{
  "detail": {
    "message": "Upload for stage 'sbom' exceeded limit",
    "max_bytes": 8388608,
    "received_bytes": 10485760
  }
}
```

**Missing Required Columns (strict mode):**

```json
{
  "detail": {
    "message": "Design CSV missing required columns (strict mode)",
    "missing_columns": ["owner", "data_class"],
    "required_columns": ["component", "subcomponent", "owner", "data_class", "description", "control_scope"]
  }
}
```

**Invalid SBOM Format (strict mode):**

```json
{
  "detail": {
    "message": "SBOM missing bomFormat and has unrecognized structure",
    "hint": "Provide bomFormat field or use a known format (CycloneDX, GitHub dependency snapshot, Syft)"
  }
}
```

**Sources:** [apps/api/app.py L612-L619](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L612-L619)

 [apps/api/app.py L645-L651](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L645-L651)

 [apps/api/app.py L720-L727](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L720-L727)

---

## Scanner-Agnostic Ingestion

In addition to format-specific endpoints, the system provides a scanner-agnostic ingestion endpoint for flexible format handling.

### Multipart Ingestion Endpoint

**Endpoint:** `POST /api/v1/ingest/multipart`

Accepts any security artifact with auto-detection of format. Uses `NormalizerRegistry` with YAML plugin configuration for extensible format support.

**Request:**

```
POST /api/v1/ingest/multipart
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="scan.sarif"
Content-Type: application/json

{...SARIF content...}
------WebKitFormBoundary--
```

**Response:**

```
{
  "status": "success",
  "format_detected": "sarif",
  "detection_confidence": 0.95,
  "findings_count": 42,
  "assets_count": 0,
  "processing_time_ms": 123,
  "findings": [...],
  "errors": [],
  "warnings": []
}
```

### Format Detection Pipeline

```mermaid
flowchart TD

Upload["Multipart Upload"]
Registry["NormalizerRegistry<br>Load config from registry.yaml"]
Detect["Detect Format<br>Test detection_patterns"]
SARIF["SARIFNormalizer<br>priority: 100"]
CycloneDX["CycloneDXNormalizer<br>priority: 90"]
SPDX["SPDXNormalizer<br>priority: 85"]
VEX["VEXNormalizer<br>priority: 80"]
CNAPP["CNAPPNormalizer<br>priority: 75"]
DarkWeb["DarkWebIntelNormalizer<br>priority: 70"]
CVEFeed["CVEFeedNormalizer<br>priority: 65"]
Confidence["confidence >= 0.7?"]
Normalize["Normalize to UnifiedFinding[]"]
Fallback["Fallback Normalizer"]
Response["IngestionResult<br>findings, assets, metadata"]

Upload -.-> Registry
Registry -.-> Detect
Detect -.-> SARIF
Detect -.-> CycloneDX
Detect -.->|"Yes"| SPDX
Detect -.-> VEX
Detect -.->|"No"| CNAPP
Detect -.-> DarkWeb
Detect -.-> CVEFeed
SARIF -.-> Confidence
CycloneDX -.-> Confidence
SPDX -.-> Confidence
VEX -.-> Confidence
CNAPP -.-> Confidence
DarkWeb -.-> Confidence
CVEFeed -.-> Confidence
Confidence -.-> Normalize
Confidence -.-> Fallback
Normalize -.-> Response
Fallback -.-> Response
```

### Supported Detection Patterns

| Format | Detection Patterns | Priority |
| --- | --- | --- |
| SARIF | `"$schema".*sarif`, `"version".*"2\.1\."`, `"runs".*\[` | 100 |
| CycloneDX | `"bomFormat".*"CycloneDX"`, `"specVersion".*"1\.[456]"` | 90 |
| SPDX | `"spdxVersion"`, `"SPDXID"`, `SPDXRef-DOCUMENT` | 85 |
| VEX | `"vulnerabilities".*"analysis"`, `"@type".*"VexDocument"` | 80 |
| CNAPP | `"cloudProvider"`, `"resourceType"`, `"securityFindings"` | 75 |
| Dark Web Intel | `"darkWebSource"`, `"threatIntelligence"`, `"credentialLeak"` | 70 |
| CVE Feed | `"CVE-[0-9]{4}-[0-9]+"`, `"cveMetadata"` | 65 |

**Sources:** [apps/api/ingestion.py L1-L800](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/ingestion.py#L1-L800)

 [config/normalizers/registry.yaml L1-L292](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/normalizers/registry.yaml#L1-L292)

---

## CLI Upload Commands

The CLI provides upload functionality for local file ingestion:

### Ingest File Command

```markdown
# Ingest single file with format detection
fixops ingest-file --file scan.sarif --output result.json

# Ingest multiple files
fixops ingest-file --file sbom.json --file sarif.json --file cve.json

# Force specific format
fixops ingest-file --file custom.json --format sarif

# Include full findings in output
fixops ingest-file --file scan.sarif --include-findings
```

**Command Flow:**

```mermaid
flowchart TD

CLI["CLI Command<br>fixops ingest-file"]
ValidateFiles["Validate File Paths"]
ReadContent["Read File Content<br>binary mode"]
CallService["IngestionService.ingest()"]
ProcessFiles["Process Each File<br>asyncio.run"]
Aggregate["Aggregate Results<br>total_findings, total_assets"]
Output["Write JSON Output<br>or print to stdout"]

CLI -.-> ValidateFiles
ValidateFiles -.-> ReadContent
ReadContent -.-> CallService
CallService -.-> ProcessFiles
ProcessFiles -.-> Aggregate
Aggregate -.-> Output
```

**Output Format:**

```
{
  "status": "success",
  "files_processed": 3,
  "total_findings": 127,
  "total_assets": 45,
  "results": [
    {
      "filename": "/path/to/sbom.json",
      "status": "success",
      "format_detected": "cyclonedx",
      "detection_confidence": 1.0,
      "findings_count": 23,
      "assets_count": 45,
      "processing_time_ms": 89,
      "errors": [],
      "warnings": []
    },
    ...
  ],
  "errors": []
}
```

**Sources:** [core/cli.py L420-L527](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/cli.py#L420-L527)

---

## Integration with Pipeline Orchestrator

After successful upload and normalization, artifacts are consumed by the PipelineOrchestrator:

```mermaid
flowchart TD

StateArtifacts["app.state.artifacts<br>{stage: normalized_object}"]
Design["design<br>dict"]
SBOM["sbom<br>NormalizedSBOM"]
SARIF["sarif<br>NormalizedSARIF"]
CVE["cve<br>NormalizedCVEFeed"]
VEX["vex<br>NormalizedVEX"]
CNAPP["cnapp<br>NormalizedCNAPP"]
Context["context<br>NormalizedBusinessContext"]
Orchestrator["PipelineOrchestrator.run()"]
Crosswalk["Build Crosswalk<br>Correlation engine"]
Enrich["EPSS/KEV Enrichment"]
Dedupe["Deduplication<br>7 strategies"]
Risk["Risk Scoring<br>Bayesian + Markov"]
Decision["Decision Engine<br>Multi-LLM consensus"]

StateArtifacts -.-> Design
StateArtifacts -.-> SBOM
StateArtifacts -.-> SARIF
StateArtifacts -.-> CVE
StateArtifacts -.-> VEX
StateArtifacts -.-> CNAPP
StateArtifacts -.-> Context
Design -.-> Orchestrator
SBOM -.-> Orchestrator
SARIF -.-> Orchestrator
CVE -.-> Orchestrator
VEX -.-> Orchestrator
CNAPP -.-> Orchestrator
Context -.-> Orchestrator
Orchestrator -.-> Crosswalk
Orchestrator -.-> Enrich
Orchestrator -.-> Dedupe
Orchestrator -.-> Risk
Orchestrator -.-> Decision
```

The orchestrator accesses artifacts via `app.state.artifacts[stage]` and combines them for comprehensive vulnerability analysis.

**Sources:** [apps/api/app.py L407-L422](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py#L407-L422)

 [apps/api/pipeline.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#LNaN-LNaN)