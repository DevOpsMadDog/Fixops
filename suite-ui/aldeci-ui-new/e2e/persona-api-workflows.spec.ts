/**
 * Persona API Workflow E2E Tests
 *
 * Tests each of the 25 enterprise personas' API workflows against
 * the live backend. Each persona's workflow steps are executed sequentially,
 * validating status codes AND response body structure/data.
 *
 * Uses Allure annotations for enterprise-grade reporting.
 */
import { test, expect } from "@playwright/test";
import { PERSONAS, API_BASE, API_TOKEN, type Persona } from "./helpers/auth";
import { PERSONA_WORKFLOWS, type WorkflowStep, type ResponseValidation } from "./helpers/endpoints";

// Rate-limit helper — small delay between API calls to avoid 429
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Execute an API request with retry-on-429 */
async function executeRequest(
  request: any,
  step: WorkflowStep,
  headers: Record<string, string>,
  url: string,
) {
  const doRequest = async () => {
    switch (step.method) {
      case "GET":    return request.get(url, { headers });
      case "POST":   return request.post(url, { headers, data: step.body });
      case "PUT":    return request.put(url, { headers, data: step.body });
      case "DELETE": return request.delete(url, { headers });
    }
  };
  let response = await doRequest();
  if (response.status() === 429) {
    await delay(3000);
    response = await doRequest();
  }
  return response;
}

/** Validate response body against rules */
function validateResponse(body: unknown, rules: ResponseValidation, label: string) {
  if (rules.isObject) {
    expect(typeof body, `${label}: response must be an object`).toBe("object");
    expect(body, `${label}: response must not be null`).not.toBeNull();
  }
  if (rules.isArray) {
    expect(Array.isArray(body), `${label}: response must be an array`).toBe(true);
    if (rules.minLength !== undefined) {
      expect((body as unknown[]).length, `${label}: array must have >= ${rules.minLength} items`).toBeGreaterThanOrEqual(rules.minLength);
    }
  }
  if (rules.hasKeys && typeof body === "object" && body !== null) {
    for (const key of rules.hasKeys) {
      expect(body, `${label}: response must have key "${key}"`).toHaveProperty(key);
    }
  }
  if (rules.bodyContains && typeof body === "string") {
    expect(body.toLowerCase()).toContain(rules.bodyContains.toLowerCase());
  }
}

for (const persona of PERSONAS) {
  const workflow = PERSONA_WORKFLOWS.find((w) => w.personaId === persona.id);
  if (!workflow) continue;

  test.describe(`P${String(persona.id).padStart(2, "0")}: ${persona.name} — ${persona.title}`, () => {
    test.describe.configure({ mode: "serial" });

    for (const step of workflow.steps) {
      test(`${step.name} [${step.method} ${step.path}]`, async ({ request }) => {
        test.info().annotations.push(
          { type: "persona", description: `${persona.name} (${persona.title})` },
          { type: "role", description: persona.role },
          { type: "endpoint", description: `${step.method} ${step.path}` },
          { type: "severity", description: "critical" },
        );

        await delay(200);

        const url = `${API_BASE}${step.path}`;
        const headers: Record<string, string> = { "X-API-Key": API_TOKEN };
        if (step.body) headers["Content-Type"] = "application/json";

        const response = await executeRequest(request, step, headers, url);

        // 1. Status code validation
        const acceptedStatuses = step.acceptStatus || [200];
        expect(
          acceptedStatuses,
          `${persona.title}: ${step.name} — expected ${acceptedStatuses.join("|")}, got ${response.status()}`
        ).toContain(response.status());

        // 2. Response body validation
        if (step.validate) {
          let body: unknown;
          try {
            body = await response.json();
          } catch {
            // Non-JSON response — skip body validation
            return;
          }
          const label = `${persona.title} → ${step.name}`;
          validateResponse(body, step.validate, label);

          // Attach validation description for Allure
          if (step.validate.description) {
            test.info().annotations.push(
              { type: "validation", description: step.validate.description },
            );
          }
        }
      });
    }
  });
}

