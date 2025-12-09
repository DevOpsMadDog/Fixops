# FixOps Agent System Architecture
## Intelligent Agents for Design-Time to Runtime Data Push

**Purpose**: Build intelligent agents that connect to systems and automatically push required data from design-time to runtime, with support for all languages.

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                    FixOps Agent Framework                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Design-Time  │  │   Runtime    │  │   Language   │         │
│  │   Agents     │  │   Agents     │  │   Agents     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│         │                 │                 │                   │
│         └─────────────────┼─────────────────┘                  │
│                           │                                     │
│                  ┌─────────▼─────────┐                          │
│                  │ Agent Orchestrator│                          │
│                  │  (Correlation)   │                          │
│                  └─────────┬─────────┘                          │
│                           │                                     │
│                  ┌─────────▼─────────┐                          │
│                  │   FixOps API       │                          │
│                  │  (Push Endpoints) │                          │
│                  └───────────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## AGENT TYPES

### 1. Design-Time Agents

**Purpose**: Monitor design-time systems and push data to FixOps.

#### Code Repository Agent
- **Monitors**: Git repositories (GitHub, GitLab, Bitbucket)
- **Pushes**: SARIF, SBOM, Design Context
- **Triggers**: New commits, pull requests, merges
- **Languages**: All supported languages

#### CI/CD Agent
- **Monitors**: CI/CD pipelines (Jenkins, GitHub Actions, GitLab CI, CircleCI)
- **Pushes**: Build artifacts, test results, deployment info
- **Triggers**: Pipeline runs, deployments

#### Design Tool Agent
- **Monitors**: Design tools (Confluence, Notion, architecture diagrams)
- **Pushes**: Design context, architecture diagrams, component mappings
- **Triggers**: Document updates, diagram changes

### 2. Runtime Agents

**Purpose**: Monitor runtime systems and push data to FixOps.

#### Container Agent
- **Monitors**: Docker, Kubernetes, containerd
- **Pushes**: Container scans, runtime metrics, security events
- **Triggers**: Container starts, image pulls, security events

#### Cloud Agent
- **Monitors**: AWS, Azure, GCP resources
- **Pushes**: Cloud scans, CSPM data, runtime metrics
- **Triggers**: Resource changes, security events

#### API Agent
- **Monitors**: API endpoints, API gateways
- **Pushes**: API scans, security events, runtime metrics
- **Triggers**: API calls, security events

### 3. Language-Specific Agents

**Purpose**: Language-specific monitoring and data collection.

#### Supported Languages:
- ✅ Python Agent
- ✅ JavaScript Agent
- ✅ Java Agent
- ✅ Go Agent
- ✅ Rust Agent
- ✅ C/C++ Agent
- ✅ Ruby Agent
- ✅ PHP Agent
- ✅ .NET Agent
- ✅ Swift Agent
- ✅ Kotlin Agent

**Each Language Agent**:
- Monitors language-specific codebases
- Uses proprietary analyzers (with OSS fallback)
- Pushes language-specific SARIF, SBOM
- Supports language-specific security patterns

---

## DATA FLOW

### Design-Time → Runtime Correlation

```
Design-Time Agent                    Runtime Agent
     │                                    │
     │ Collects:                          │ Collects:
     │ - SARIF                            │ - Container scans
     │ - SBOM                             │ - Runtime metrics
     │ - Design context                   │ - Security events
     │                                    │
     └──────────┬─────────────────────────┘
                │
                ▼
        Agent Orchestrator
                │
                │ Correlates:
                │ - Code → Container
                │ - Component → Runtime
                │ - Design → Deployment
                │
                ▼
          FixOps API
                │
                │ Pushes:
                │ - Correlated data
                │ - Design-time data
                │ - Runtime data
                │
                ▼
          FixOps Engine
```

---

## AGENT CONFIGURATION

### Overlay Configuration

```yaml
# config/fixops.overlay.yml

agents:
  enabled: true
  fixops_api_url: https://api.fixops.com
  fixops_api_key: ${FIXOPS_API_KEY}
  
  # Design-time agents
  design_time:
    code_repo:
      enabled: true
      agents:
        - agent_id: github-main-repo
          repo_url: https://github.com/org/repo
          branch: main
          polling_interval: 60
          push_sarif: true
          push_sbom: true
          push_design_context: true
    
    cicd:
      enabled: true
      agents:
        - agent_id: github-actions
          provider: github_actions
          repo: org/repo
          polling_interval: 30
    
    design_tool:
      enabled: true
      agents:
        - agent_id: confluence-architecture
          tool: confluence
          space_key: ARCH
          polling_interval: 300
  
  # Runtime agents
  runtime:
    container:
      enabled: true
      agents:
        - agent_id: docker-runtime
          runtime: docker
          polling_interval: 60
          scan_images: true
          collect_metrics: true
        
        - agent_id: k8s-cluster-prod
          runtime: kubernetes
          cluster: production
          polling_interval: 60
    
    cloud:
      enabled: true
      agents:
        - agent_id: aws-prod
          provider: aws
          region: us-east-1
          polling_interval: 300
        
        - agent_id: azure-prod
          provider: azure
          subscription: prod-sub
          polling_interval: 300
    
    api:
      enabled: true
      agents:
        - agent_id: api-gateway-prod
          gateway: aws-api-gateway
          polling_interval: 60
  
  # Language-specific agents
  languages:
    python:
      enabled: true
      agents:
        - agent_id: python-main-repo
          repo_url: https://github.com/org/python-repo
          branch: main
          use_proprietary: true
          oss_fallback: true
    
    javascript:
      enabled: true
      agents:
        - agent_id: js-frontend-repo
          repo_url: https://github.com/org/frontend
          branch: main
    
    java:
      enabled: true
      agents:
        - agent_id: java-backend-repo
          repo_url: https://github.com/org/backend
          branch: main
    
    # ... other languages
  
  # Correlation rules
  correlation:
    enabled: true
    rules:
      - name: code_to_container
        design_fields: [repo_url, commit, component]
        runtime_fields: [image, container_id]
        confidence: 0.9
      
      - name: component_to_runtime
        design_fields: [component_name, version]
        runtime_fields: [deployed_component, version]
        confidence: 0.85
```

---

## IMPLEMENTATION STATUS

### ✅ **COMPLETED**
- ✅ Agent Framework (`/workspace/agents/core/agent_framework.py`)
- ✅ Agent Orchestrator (`/workspace/agents/core/agent_orchestrator.py`)
- ✅ Code Repository Agent (`/workspace/agents/design_time/code_repo_agent.py`)
- ✅ Container Agent (`/workspace/agents/runtime/container_agent.py`)
- ✅ Python Agent (`/workspace/agents/language/python_agent.py`)

### ⚠️ **TO BUILD**

#### Design-Time Agents:
- ⚠️ CI/CD Agent
- ⚠️ Design Tool Agent

#### Runtime Agents:
- ⚠️ Cloud Agent (AWS/Azure/GCP)
- ⚠️ API Agent

#### Language Agents:
- ⚠️ JavaScript Agent
- ⚠️ Java Agent
- ⚠️ Go Agent
- ⚠️ Rust Agent
- ⚠️ C/C++ Agent
- ⚠️ Ruby Agent
- ⚠️ PHP Agent
- ⚠️ .NET Agent
- ⚠️ Swift Agent
- ⚠️ Kotlin Agent

---

## USAGE EXAMPLE

```python
from agents.core.agent_framework import AgentFramework, AgentConfig, AgentType
from agents.design_time.code_repo_agent import CodeRepoAgent
from agents.runtime.container_agent import ContainerAgent
from agents.language.python_agent import PythonAgent

import asyncio


async def main():
    # Initialize framework
    framework = AgentFramework(
        fixops_api_url="https://api.fixops.com",
        fixops_api_key="your-api-key"
    )

    # Create design-time agent
    code_repo_config = AgentConfig(
        agent_id="github-main-repo",
        agent_type=AgentType.DESIGN_TIME,
        name="GitHub Main Repository",
        enabled=True,
        polling_interval=60,
    )

    code_repo_agent = CodeRepoAgent(
        config=code_repo_config,
        fixops_api_url="https://api.fixops.com",
        fixops_api_key="your-api-key",
        repo_url="https://github.com/org/repo",
        repo_branch="main",
    )

    # Create runtime agent
    container_config = AgentConfig(
        agent_id="docker-runtime",
        agent_type=AgentType.RUNTIME,
        name="Docker Runtime",
        enabled=True,
        polling_interval=60,
    )

    container_agent = ContainerAgent(
        config=container_config,
        fixops_api_url="https://api.fixops.com",
        fixops_api_key="your-api-key",
        container_runtime="docker",
    )

    # Create language-specific agent
    python_config = AgentConfig(
        agent_id="python-main-repo",
        agent_type=AgentType.LANGUAGE,
        name="Python Main Repository",
        enabled=True,
        polling_interval=60,
    )

    python_agent = PythonAgent(
        config=python_config,
        fixops_api_url="https://api.fixops.com",
        fixops_api_key="your-api-key",
        repo_url="https://github.com/org/python-repo",
        repo_branch="main",
    )

    # Register agents
    framework.register_agent(code_repo_agent)
    framework.register_agent(container_agent)
    framework.register_agent(python_agent)

    # Start all agents
    await framework.start_all()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## BENEFITS

1. **Automatic Data Push**: No manual uploads needed
2. **Real-Time Monitoring**: Continuous monitoring of systems
3. **Design-to-Runtime Correlation**: Links design-time to runtime
4. **Language Support**: Production agents for Python, JavaScript, Java, and Go today; additional languages queued on roadmap
5. **OSS Fallback**: Uses OSS tools if proprietary fails
6. **Scalable**: Can monitor hundreds of systems
7. **Flexible**: Configurable via overlay

---

## NEXT STEPS

1. **Build Remaining Agents**: Complete all design-time, runtime, and language agents
2. **Test Integration**: Test with real systems
3. **Add More Languages**: Support all 12+ languages
4. **Enhance Correlation**: Improve design-to-runtime correlation
5. **Add Monitoring**: Agent health monitoring and alerting

---

## CONCLUSION

**Agent system built** for automatic data push from design-time to runtime.

**Supports key languages today** (Python, JavaScript, Java, Go) with clear path to broaden coverage.

**Configurable via overlay** for flexible deployment.

**Ready to extend** with additional agents and features.
