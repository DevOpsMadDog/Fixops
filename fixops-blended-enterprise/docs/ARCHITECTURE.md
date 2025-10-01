# FixOps Architecture - Technical Design

## 📊 3. Processing Layer
### Purpose
Model threat evolution, prioritize vulnerabilities, and generate human-readable insights.

### Subcomponents and Algorithms

#### 👑 Bayesian Prior Mapping (Custom)
- **Purpose**: Assign probabilities to components based on SSVC context
- **Inputs**:
  - Business logic, exposure, and criticality
  - Use `pgmpy` or `pomegranate` for Bayesian inference

#### ⚙️ Markov Transition Matrix Builder (Custom)  
- **Purpose**: Define model state transitions (e.g., Secure → Vulnerable → Exploited → Patched)
- **Inputs**:
  - CVE disclosure dates, EPSS scores, KEV flags
  - Use `mchmm` to define and simulate transitions

#### ✅ SSVC + Probabilistic Fusion Logic (Custom)
- **Purpose**: Combine deterministic SSVC decisions with probabilistic risk scores
- **Logic**:
  - Fuse SSVC vector outcomes with Bayesian/Markov outputs
  - Generate composite risk scores

#### 🧠 SARIF-Based Non-CVE Vulnerability Handling (Custom)
- **Purpose**: Handle scanner findings without CVEs 
- **Process**:
  - Parse SARIF JSON to extract metadata
  - Infer risk probabilities based on CWE/OWASP mapping
  - Cluster similar findings for shared risk profiles

#### 📊 Knowledge Graph Construction  
- **Purpose**: Link components, vulnerabilities, and context
- **Tools**: 
  - Use `CTINexus` for entity extraction and graph visualization

#### 🧠 LLM Explanation Engine
- **Purpose**: Generate human-readable summaries
- **Implementation**: Use models from [Awesome-LLM4Cybersecurity](https://github.com/tmylla/Awesome-LLM4Cybersecurity)

## 🧠 4. Decision Layer
### Purpose
Aggregate insights and compute final risk scores.

### Logic
- Combine SSVC decisions, Bayesian updates, Markov transitions, and graph relationships
- Rank vulnerabilities based on stakeholder impact and exploit likelihood

### Output
- Actionable risk scores and remediation priorities

## 📊 5. Output / Feedback Loop
### Purpose  
Deliver insights and improve future design decisions.

### Interfaces
#### Dashboards: Use `Streamlit` or `Grafana`
#### API: Use `FastAPI` or `Flask` 
#### CLI: Use `Typer` or `Click`

### Feedback
- Update SSVC priors based on historical decisions and outcomes

## ✅ Summary of Reusable OSS Components

| Layer | Function | OSS Component |
|-------|----------|---------------|
| Design Stage | SSVC Prep | `python-ssvc` |
| Input Layer | SBOM parsing | `lib4sbom` |
| Input Layer | SARIF conversion | `snyk-to-sarif` |
| Processing Layer | Markov modeling | `mchmm` |
| Processing Layer | Bayesian modeling | `pgmpy` |
| Processing Layer | Knowledge graph visualization | `CTINexus` |
| Output Layer | Dashboard/API/CLI | `Streamlit` |

## ⚙️ Summary of Custom Algorithms

| Algorithm | Purpose |
|-----------|---------|
| Bayesian Prior Mapping | Assign initial risk probabilities to components based on SSVC context |
| Probabilistic Fusion Logic | Combine SSVC decisions with threat modeling |
| SSVC + Probabilistic Fusion Logic | Combine deterministic and probabilistic approaches |
| SARIF-Based Non-CVE Vulnerability Handling | Normalize and score scanner findings without CVEs |
| Knowledge Graph Construction | Link vulnerabilities and context |
| LLM Explanation Engine | Generate human-readable summaries |
