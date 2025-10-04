# Agentic AI Landscape & FixOps Enablement

This note summarises the current generation of agentic AI frameworks, highlights the architectural
patterns they employ, and outlines how FixOps can provide contextual assurance when teams adopt these
stacks.

## Framework Landscape

| Framework | Primary Focus | Characteristics | Operational Concerns |
| --------- | -------------- | ---------------- | -------------------- |
| **LangChain** | General-purpose agent/tooling orchestration | Python/JS SDK, tool abstractions, conversation memory, retrieval modules | Tool misuse, prompt injection via tool selection, secrets flowing through callbacks |
| **AutoGPT** | Autonomous goal-seeking agent | Looping plan/execute/reflect cycles, plugin system for actions | Unbounded filesystem/network access, runaway resource usage, difficulty constraining scope |
| **CrewAI** | Multi-agent collaboration | Role-based agents (Planner/Researcher/Reviewer), shared task board | Coordination drift between agents, inconsistent guardrails per role |
| **Hugging Face Agents** | Hosted tool-calling agents | Hosted inference, declarative tool registry, hub integrations | Third-party API dependency, remote tool execution, data residency |
| **LlamaIndex (GPT Index)** | Retrieval-augmented agents | Vector stores, structured index abstractions, query engines | Sensitive data indexing, schema drift between sources, overexposure of proprietary knowledge |

## Common Building Blocks

1. **Planner / Controller** — decides which tools to invoke and in what order (e.g., LangChain Agent,
   AutoGPT loop). Typically relies on LLM reasoning with temperature > 0, making behaviour non-
   deterministic.
2. **Tooling Layer** — wrappers around HTTP APIs, databases, vector stores, browsers, or shell access.
   Tool metadata is often developer-supplied YAML/JSON without schema validation.
3. **Memory / State Stores** — vector embeddings, conversation buffers, or scratchpads used between
   turns. These frequently live in Redis, Postgres, or hosted SaaS services.
4. **Observation Channels** — output persisted to logs, tickets, or direct user responses; some
   frameworks allow streaming tokens for partial progress.

## Security & Governance Challenges

- **Prompt Injection & Tool Hijacking** — untrusted inputs can instruct agents to call destructive
  tools or exfiltrate data. Controls: allowlists, contextual risk scoring, human approval gates.
- **Supply Chain & Dependency Drift** — dependencies pulled from GitHub/PyPI/Node ecosystems change
  rapidly; licensing and security posture vary.
- **Auditability** — agent runs often involve multiple tool invocations; capturing evidence (inputs,
  outputs, justification) is necessary for regulated teams.
- **Data Minimisation** — retrieving proprietary datasets into LLM prompts can leak sensitive
  information to model providers or memory stores.

## How FixOps Contributes

The updated overlay schema and pipeline now expose the **AI Agent Advisor**, which:

- Loads `ai_agents.framework_signatures` from the overlay, matching components and design notes
  against curated keywords for LangChain, AutoGPT, CrewAI, Hugging Face Agents, and LlamaIndex.
- Pulls `ai_agents.controls` to surface recommended guardrails (prompt logging, tool scopes, manual
  approvals) directly in the pipeline output and evidence bundle.
- Maps frameworks to `ai_agents.playbooks`, steering triage teams to channels such as `appsec-ai` or
  `sre-risk` depending on the agent type.

FixOps can now demonstrate tangible CTEM coverage for agentic workloads:

1. **Contextual Risk Scoring** — the existing context engine combines business criticality with AI
   watchlist hits to elevate agentic services during pipeline runs.
2. **Policy Automation** — guardrail failures or high-risk agents can auto-generate Jira/Confluence
   tasks, keeping remediation workflows aligned with AI governance requirements.
3. **Evidence Hub Integration** — evidence bundles (when configured) now include `ai_agent_analysis`,
   ensuring audits capture which frameworks were detected, recommended controls, and assigned
   playbooks.
4. **Feedback Capture** — the `/feedback` endpoint allows CISOs/AppSec leaders to log override
   decisions or waivers tied to specific agent runs, creating a defensible audit trail.

## Emerging Areas to Monitor

- **LLM Gateway Services** (e.g., OpenAI Assistants, Anthropic API) — may consolidate tooling and
  reduce need for self-hosted orchestration but still require context-aware controls.
- **Secure Toolchains** — frameworks introducing policy DSLs (Guardrails AI, Outlines) could integrate
  with FixOps policy automation to enforce approval gates.
- **Agent Observability** — open-source projects like LangSmith or Weights & Biases traces provide
  telemetry FixOps could ingest for richer evidence bundles.

## Secure SDLC (SSDLc) Gaps in Agentic Stacks

While the leading frameworks accelerate experimentation, most teams building AI agents or Model
Context Protocol (MCP) services leave material SSDLc gaps unaddressed:

1. **Plan / Threat Modelling** — Few projects document attacker goals (prompt injection, tool
   escalation, model theft). FixOps can require design artefacts that catalogue agent roles, tool
   scopes, and threat assumptions so the context engine can flag omissions during the planning stage.
2. **Code / Dependency Hygiene** — Agent repos often pin neither model SDK versions nor tool plugins,
   so supply-chain drift is common. Guardrail policies should enforce SBOM uploads plus licensing and
   vulnerability scans per agent component.
3. **Build / Test Gates** — CI pipelines rarely exercise adversarial prompts or fail when agents call
   prohibited tools. FixOps policy automation can mark such gaps and emit Jira tasks until adversarial
   test suites (red-teaming, jailbreak prompts) are wired in.
4. **Deploy Controls** — Runtime approvals for high-risk tools or external API calls are often missing.
   Overlay-driven playbooks can insist on human-in-the-loop approval or access tokens scoped to
   read-only actions before Enterprise promotion.
5. **Run / Monitoring** — Teams seldom record tool invocations, prompt/response history, or data flow
   provenance. The evidence hub can ensure observability feeds (logs, LangSmith traces) are attached to
   each release package and retained for audits.
6. **Audit & Feedback** — Waivers for risky behaviours are typically ad hoc. FixOps’ feedback capture
   provides structured review trails so CISOs can correlate override reasons with future rescoring.

By enforcing these artefacts through the overlay configuration, FixOps complements the raw agentic
capabilities with a defensible SSDLc spine that Apiiro and Aikido have not yet optimised for
agent-focused workloads.

The platform now encodes those checkpoints directly in the overlay (`ssdlc.stages`) and the pipeline
emits an `ssdlc_assessment` block that highlights satisfied, in-progress, and missing lifecycle
controls alongside guardrails, policy automation, and evidence bundles.

The overlay-driven approach ensures these integrations remain configuration-first: teams extend the
watchlist or control sets without redeploying the service, while FixOps centralises visibility across
traditional vulnerability data and emerging agentic workloads.
