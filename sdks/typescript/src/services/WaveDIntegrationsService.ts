/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AgentTaskRequest } from '../models/AgentTaskRequest';
import type { apps__api__wave_d_integrations_router__StageMatrixRequest } from '../models/apps__api__wave_d_integrations_router__StageMatrixRequest';
import type { AutoWaiverRuleRequest } from '../models/AutoWaiverRuleRequest';
import type { ConnectorMappingDryRun } from '../models/ConnectorMappingDryRun';
import type { ConnectorMappingRequest } from '../models/ConnectorMappingRequest';
import type { CopilotGraphNLRequest } from '../models/CopilotGraphNLRequest';
import type { CrownJewelTagRequest } from '../models/CrownJewelTagRequest';
import type { EASMSeedDomainRequest } from '../models/EASMSeedDomainRequest';
import type { SanctionedAIServiceRequest } from '../models/SanctionedAIServiceRequest';
import type { StageEvaluateRequest } from '../models/StageEvaluateRequest';
import type { TrustGraphCompactRequest } from '../models/TrustGraphCompactRequest';
import type { WebhookSubscribeRequest } from '../models/WebhookSubscribeRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveDIntegrationsService {
    /**
     * Create Connector Mapping
     * Persist a single field mapping for a connector. (Multica e194a1b1)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createConnectorMappingApiV1ConnectorsMappingPost(
        requestBody: ConnectorMappingRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/mapping',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Dry Run Connector Mapping
     * Apply mappings to a sample payload without side effects. (Multica 4e2d5913)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dryRunConnectorMappingApiV1ConnectorsMappingDryRunPost(
        requestBody: ConnectorMappingDryRun,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/mapping/dry-run',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Webhook Event Catalogue
     * Return the catalogue of available webhook event types. (Multica 67a3167b)
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static webhookEventCatalogueApiV1WebhooksEventCatalogueGet(
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/event-catalogue',
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Webhook Subscribe
     * Register a webhook subscription. (Multica d36e7e48)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static webhookSubscribeApiV1WebhooksSubscribePost(
        requestBody: WebhookSubscribeRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/subscribe',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Easm Seed Domain
     * Seed an EASM root domain. (Multica 2ccc15a7)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static easmSeedDomainApiV1EasmSeedDomainPost(
        requestBody: EASMSeedDomainRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/easm/seed-domain',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Easm Subsidiaries
     * List discovered subsidiaries for an org. (Multica 828b955d)
     * @param org
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static easmSubsidiariesApiV1EasmSubsidiariesOrgGet(
        org: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/easm/subsidiaries/{org}',
            path: {
                'org': org,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Easm Exposures
     * Return exposures filtered by confidence. (Multica 0476b668)
     * @param confidence
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static easmExposuresApiV1EasmExposuresGet(
        confidence?: number,
        limit: number = 100,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/easm/exposures',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'confidence': confidence,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Copilot Graph Nl Query
     * Run a natural-language query against the TrustGraph. (Multica 0817d38c)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static copilotGraphNlQueryApiV1CopilotGraphNlQueryPost(
        requestBody: CopilotGraphNLRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/copilot/graph-nl-query',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Copilot Traversal Trace
     * Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)
     * @param qId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static copilotTraversalTraceApiV1CopilotQIdTraversalTraceGet(
        qId: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/copilot/{q_id}/traversal-trace',
            path: {
                'q_id': qId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Ai Exposure Shadow
     * List discovered shadow AI services. (Multica 3e63ac8d)
     * @param flagUnregistered
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static aiExposureShadowApiV1AiExposureShadowGet(
        flagUnregistered: boolean = true,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ai-exposure/shadow',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'flag_unregistered': flagUnregistered,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Ai Exposure Sanctioned List
     * Add an approved/sanctioned AI service. (Multica 5040fb06)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static aiExposureSanctionedListApiV1AiExposureSanctionedListPost(
        requestBody: SanctionedAIServiceRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-exposure/sanctioned-list',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Dispatch Agent Task
     * Dispatch a task to a named agent role (security_analyst, pentester, etc).
     *
     * (Multica 37c6a559)
     * @param role
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dispatchAgentTaskApiV1AgentsRoleTaskPost(
        role: string,
        requestBody: AgentTaskRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/agents/{role}/task',
            path: {
                'role': role,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Tag Crown Jewel
     * Tag an asset as a crown-jewel (or untag). (Multica 68162b9b)
     * @param id
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static tagCrownJewelApiV1AssetsIdCrownJewelTagPost(
        id: string,
        requestBody: CrownJewelTagRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/assets/{id}/crown-jewel-tag',
            path: {
                'id': id,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Trustgraph Compact
     * Run TrustGraph compaction. (Multica d532f156)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static trustgraphCompactApiV1TrustgraphCompactPost(
        requestBody: TrustGraphCompactRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/compact',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Trustgraph Quality Issues
     * Return TrustGraph data-quality issues. (Multica 9f0ae4e6)
     * @param severity
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static trustgraphQualityIssuesApiV1TrustgraphQualityIssuesGet(
        severity?: (string | null),
        limit: number = 100,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/quality-issues',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'severity': severity,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Waivers
     * List waivers, optionally filtered to auto-applied ones. (Multica 49049e61)
     * @param auto
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listWaiversApiV1WaiversGet(
        auto: boolean = false,
        limit: number = 100,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/waivers',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'auto': auto,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Auto Waiver Rule
     * Register an auto-waiver rule. (Multica 1f5d8fc9)
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createAutoWaiverRuleApiV1AutoWaiverRulesPost(
        requestBody: AutoWaiverRuleRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auto-waiver-rules',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Set Policy Stage Matrix
     * Set the CTEM stage matrix for a policy. (Multica 61db07fb)
     * @param id
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static setPolicyStageMatrixApiV1PoliciesIdStageMatrixPost(
        id: string,
        requestBody: apps__api__wave_d_integrations_router__StageMatrixRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/{id}/stage-matrix',
            path: {
                'id': id,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy Stage Matrix
     * Return the CTEM stage matrix for a policy. (Multica 181dc9f8)
     * @param id
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyStageMatrixApiV1PoliciesIdStageMatrixGet(
        id: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies/{id}/stage-matrix',
            path: {
                'id': id,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Evaluate At Stage
     * Evaluate a context against stage-aware policies. (Multica a0585e59)
     * @param stage
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static evaluateAtStageApiV1EvaluatePost(
        stage: string,
        requestBody: StageEvaluateRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/evaluate',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'stage': stage,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
