# @aldeci/client

Typed TypeScript/JavaScript client for the [ALDECI Security Intelligence Platform](https://github.com/DevOpsMadDog/Fixops) API.

Auto-generated from the live OpenAPI 3.1 spec (800+ endpoints). Uses the native `fetch` API — no extra HTTP dependencies required.

## Installation

```bash
npm install @aldeci/client
# or
yarn add @aldeci/client
# or
pnpm add @aldeci/client
```

## Quick Start

```typescript
import { AldeciClient } from "@aldeci/client";

const client = new AldeciClient({
  BASE: "https://your-aldeci-instance.example.com",
  TOKEN: "your-api-token",
});

// List high-severity issues
const issues = await client.issues.getIssues({ severity: "high" });
for (const issue of issues) {
  console.log(issue.title, issue.severity);
}
```

## Configuration

```typescript
import { OpenAPI } from "@aldeci/client";

// Global configuration
OpenAPI.BASE = "https://your-aldeci-instance.example.com";
OpenAPI.TOKEN = "your-api-token";

// Or per-request token resolver (async)
OpenAPI.TOKEN = async () => {
  return await getTokenFromVault();
};
```

## Usage Examples

### Assets and SBOM

```typescript
import { AssetsService, SbomService } from "@aldeci/client";

// Get asset inventory
const assets = await AssetsService.getAssets({ page: 1, pageSize: 50 });

// Generate SBOM for a repository
const sbom = await SbomService.generateSbom({ repoId: "repo-uuid" });
```

### Connectors

```typescript
import { ConnectorsService } from "@aldeci/client";

// List all connectors
const connectors = await ConnectorsService.getConnectors();

// Trigger a sync
await ConnectorsService.syncConnector({ connectorId: "connector-uuid" });
```

### Compliance

```typescript
import { ComplianceService } from "@aldeci/client";

// Get SOC2 compliance posture
const posture = await ComplianceService.getFrameworkPosture({
  framework: "soc2",
});
console.log(`Score: ${posture.score}%`);
```

## API Coverage

This client covers all 800+ ALDECI API endpoints including:

- **Issues** — vulnerability findings, severity triage, risk scoring
- **Assets** — inventory, SBOM, software composition analysis
- **Brain Pipeline** — AI analysis, LLM consensus, neural map
- **Connectors** — GitHub, GitLab, Jira, AWS, Azure, GCP integrations
- **Compliance** — SOC2, ISO27001, NIST, PCI-DSS, HIPAA frameworks
- **Threat Intelligence** — 28+ feed sources, CVE enrichment
- **Playbooks** — automated remediation workflows
- **Admin** — organizations, users, tokens, billing, MCP gateway

## Requirements

- Node.js 18+
- TypeScript 5.0+ (for TypeScript projects)

## Error Handling

```typescript
import { ApiError } from "@aldeci/client";

try {
  const result = await client.issues.getIssues();
} catch (err) {
  if (err instanceof ApiError) {
    console.error(`API error ${err.status}: ${err.message}`);
  }
}
```

## License

MIT
