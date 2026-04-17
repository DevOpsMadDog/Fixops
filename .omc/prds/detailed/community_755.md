# PRD — Community 755: Bash Default-Pathnames Header (pathnames.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Review Needed
**Effort:** XS – vendor file; may need review for containerised ALDECI deployments
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define absolute filesystem paths (DEFAULT_HOSTS_FILE=/etc/hosts, DEFAULT_MAIL_DIR, etc.) for bash-5.1 defaults, allowing the ALDECI-embedded bash to locate system files on the host OS.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/pathnames.h`
- Graph community: 755 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[pathnames.h] -->|defines| B[DEFAULT_HOSTS_FILE=/etc/hosts]
    A -->|defines| C[DEFAULT_MAIL_DIR / DEFAULT_INFO_FILE]
    B & C --> D[bash-5.1 mailcheck.c / general.c]
    D --> E[Path resolution in ALDECI container environment]
```

---

## Source Files

- `bash-5.1/pathnames.h`

**Graph node label (truncated):** `pathnames.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/pathnames.h:L25 – #define DEFAULT_HOSTS_FILE '/etc/hosts'

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 755 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/mailcheck.c`
- `docker/Dockerfile`

---

## Acceptance Criteria

- [ ] /etc/hosts readable in ALDECI container; hostname completion works

---

## Effort Estimate

**XS – vendor file; may need review for containerised ALDECI deployments**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Verify vendored build compiles cleanly | 2 |
| CI build matrix validation | 2 |

---

## Status

**Review Needed**

> Vendored file. No ALDECI-side changes required. Only action: ensure bash-5.1 builds cleanly in CI and GPLv3 license headers are preserved.
