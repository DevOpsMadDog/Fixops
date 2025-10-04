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

The overlay-driven approach ensures these integrations remain configuration-first: teams extend the
watchlist or control sets without redeploying the service, while FixOps centralises visibility across
traditional vulnerability data and emerging agentic workloads.
