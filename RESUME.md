# Resume here

One page. Read this, run one script, keep going.

```bash
./scripts/setup-toolchain.sh          # install / repair everything
./scripts/setup-toolchain.sh --check  # report only, changes nothing
```

Then **restart Claude Code** if it installed `@ast-grep/napi` — the MCP server
binds native modules at startup and will not pick it up mid-session.

---

## The toolchain, and why each one is here

Every choice below was measured on this repository — 2.2M LOC, 5,829 Python
files. The reasoning is in `docs/TOOLING_ASSESSMENT_2026-08-25.md`.

| Tool | Job | Trust it for | Do not trust it for |
|---|---|---|---|
| **ast-grep** (via omc) | structural query | "what exists / who calls this" | — |
| **Hydra** | model routing | running cheap work on Haiku | its "72% bug detection" — unmeasured |
| **repomix** | packing, secret gate | token-weight god-file ranking | secret hits without triage |
| **UA structural** | free tree-sitter map | `./scripts/ua-structure.sh` — 947 files in 5.8s | — |
| **UA semantic** | LLM knowledge graph | scoped `/understand <path>` | unscoped runs (~580 dispatches) |
| **Multica** | task board | the 7 todo / 10 in-progress / 5 blocked | scheduling — its agent tables are empty |

### The one number that governs everything

```
Read brain_pipeline.py in full ....... 64,689 tokens
Same question via symbol outline .......... 35 tokens
                                        ─────────────
                                          1,848x
```

Full-file reads are essentially the entire token bill. So: **outline before
read, filter every tool call, scope every UA run, delegate cheap work.**

### Two tools we removed, and exactly why

**graphify — dropped, and replaced.** Its call graph is false. The most-connected node in the
entire codebase was `sast_router_policystate_get` with 11,791 edges: a
three-line thread-safe dict getter, because graphify collapses every `.get()`
call in the repo into that node. `graphify path brain_pipeline
security_findings_engine` returned a 4-hop path routed through `.get()`
connecting two unrelated **test** files. Its only unique output was community
clustering, which nothing consumed, and its cache was 534 MB. repomix's
token-weight ranking is a better god-file signal, ast-grep answers structural
questions directly, and **UA's free tree-sitter layer does graphify's actual job
properly** — 947 files in 5.8 seconds versus 20 minutes, with call targets
qualified (`data.get`, `conn.execute`) rather than collapsed. Its first run
surfaced a real fact graphify never could: `conn.execute` 8,544 times and
`self._conn` 3,729, meaning nearly every engine opens its own SQLite connection.

**ruflo — dropped.** Not a config problem — the object model is broken. Verified on
v3.7.0-alpha.7: `task create` mints an id, `task status <id>` returns
`Task: undefined`, `task assign` dies on `Cannot read properties of undefined
(reading 'join')`, and a spawned agent sits `idle` beside a `pending` task
forever. Hydra works because it does **not** own execution — it writes standard
`.claude/agents/*.md` and lets native dispatch run them.

---

## Where the product actually stands

**Queue: 11 of 31 closed** — `docs/OPEN_QUEUE.md` is the single source of truth.
The closed ones are the load-bearing ones.

Verified working **in production** (fly, `aldeci.fly.dev`):

- **Flow 02 — the spine.** Ingest real scanner output → see it → triage it →
  it persists, in the uploader's own tenant.
- **Flow 04 — the assessor path.** Evidence bundles are generated, sealed into a
  chain of custody, and **signed**. Tamper is provably detected: editing a
  sealed bundle to claim `controls_effective: 999` returns
  `content_integrity: "tampered"`. An auditor can verify **without us** via
  `scripts/verify_evidence_bundle.py` — no network, no FixOps.
- **The P0.** A customer API key could read *and write* any other tenant by
  naming it in a URL. Closed across `513cdc13` + `9ca5afb3`; details and
  reproduction in `docs/SECURITY_FINDING_cross_tenant_org_id.md`.
- **Exploitability.** Reachability × exploit evidence fused into one verdict
  (act_now / schedule / watch / defer), each carrying whether its evidence was
  *measured* or *estimated*.
- **Customer-declarable graph.** A tenant declares its own entity types and
  correlation rules; rules can move priority and attach labels but are refused
  (HTTP 400) if they try to assert a measurement.

**Gates:** 2,209 tests. `docs/COMPETITIVE_POSITION_2026-08-25.md` separates what
was verified by running it from what is **not yet true** — read that before any
sales conversation.

---

## The new console

`suite-ui/aldeci-ui-new/src/console/` — eight flows, ⌘K palette, persona lens,
**no login** (key comes from config; see `console/api.ts`).

The old ~300-page surface is still mounted behind `VITE_LEGACY_UI=1`. Deliberately
reversible: twice this month something that looked dead turned out to be
load-bearing.

```bash
cd suite-ui/aldeci-ui-new && npx vite --port 5173
```

**Verified in a browser:** Triage renders 2 real findings with real CVEs and
severities. The other six screens are built but **not yet browser-verified** —
that is the next task, and it matters, because verifying Triage is what exposed
the empty-CVE bug (ingest was storing the CVE only in the title, which silently
starved reachability analysis).

---

## Next, in order

1. **Browser-verify the six unverified console screens.** Every defect this
   month came from pressing a button and reading the value back.
2. **Re-measure Q1** — "~80 dead screens" is stale. Several root causes are
   fixed (the error envelope that made "no data yet" read as "endpoint not
   found"; split stores; the tenancy bug filing everything into `default`).
3. **Q8** — reachability's noise-reduction percentage on a real customer repo.
   It is the first number a buyer asks for and we cannot yet quote it.

## Standing rules that caught everything

1. Click it, then read the data back.
2. A number nobody measured must not be displayed.
3. Absence is a fact worth stating — "not configured" beats an invented zero.
4. Two components can each be correct while the product lies. Check the join.
5. Defensive code must not degrade into the failure it defends against.
6. The client never decides its own privileges.
