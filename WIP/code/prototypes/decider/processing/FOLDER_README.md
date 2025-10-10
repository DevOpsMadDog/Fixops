# new_apps/api/processing/

**Purpose:** Shared logic for the decision-engine demo, including SARIF processing, knowledge graph
helpers, and human-readable explanations.

**Key Files**
- `sarif.py` — Normalises SARIF findings for decision scoring.
- `knowledge_graph.py` — Simulates relationships between components and risks.
- `explanation.py` — Generates narrative justifications for automated decisions.

**Module API**
- Functions return plain Python dictionaries/lists to keep the FastAPI layer thin.

**Data In/Out**
- Inputs: Parsed SARIF records, component metadata, and rule definitions.
- Outputs: Aggregated stats and explanation strings consumed by API responses.

**Gotchas**
- Modules assume SARIF schema compliance; add validation before using in production.
- Graph helpers are deterministic—extend with real graph databases when scaling beyond demo.
