# PRD: Community 272 — Bash Loadable Builtin — Perl Interpreter Bridge (iperl)

## Master Goal Mapping
**Goal:** Embed a Perl interpreter as a bash loadable builtin, enabling inline Perl execution within bash scripts without forking a perl process.

**Domain:** Infrastructure / Shell Utilities
**Personas:** Platform Engineer, Security Researcher
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/examples/loadables/perl/iperl.c`

## Graph Nodes (Labels)
- iperl.c
- perl_main()

---

## Architecture Diagram

```mermaid
graph TD
    A[bash shell] --> B[iperl loadable]
    B --> C[perl_main()]
    C --> D[libperl embedded interpreter]
    D --> E[Perl script execution]
```

---

## Code Proof

- `bash-5.1/examples/loadables/perl/iperl.c:L1-L80` — perl_main() initializes Perl interpreter, eval_pv() runs scripts

---

## Inter-Dependencies

- `libperl.so`
- `PERL_SYS_INIT3`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
bash → enable -f iperl → perl_main(argc,argv) → Perl interpreter → result to bash $?
```

---

## Referenced Docs

- `perlembed(1)`
- `bash-5.1/examples/loadables/perl/README`

---

## Acceptance Criteria

- [ ] iperl -e "print 1+1" outputs 2
- [ ] Perl errors propagate as bash exit codes
- [ ] Memory cleaned up after each call

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
