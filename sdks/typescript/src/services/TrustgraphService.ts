/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__trustgraph_routes__IngestRequest } from '../models/apps__api__trustgraph_routes__IngestRequest';
import type { apps__api__trustgraph_routes__QueryRequest } from '../models/apps__api__trustgraph_routes__QueryRequest';
import type { apps__api__trustgraph_routes__SearchResponse } from '../models/apps__api__trustgraph_routes__SearchResponse';
import type { CoreResponse } from '../models/CoreResponse';
import type { EntityResponse } from '../models/EntityResponse';
import type { QueryResponse } from '../models/QueryResponse';
import type { RelateRequest } from '../models/RelateRequest';
import type { RelateResponse } from '../models/RelateResponse';
import type { SearchRequest } from '../models/SearchRequest';
import type { ToolSchema } from '../models/ToolSchema';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TrustgraphService {
    /**
     * Query Trustgraph
     * Execute natural language query across Knowledge Cores.
     *
     * Args:
     * req: Query request
     * org_id: Organization ID
     *
     * Returns:
     * Query result with answer, evidence, and confidence
     * @param requestBody
     * @param orgId
     * @returns QueryResponse Successful Response
     * @throws ApiError
     */
    public static queryTrustgraphApiV1TrustgraphQueryPost(
        requestBody: apps__api__trustgraph_routes__QueryRequest,
        orgId?: (string | null),
    ): CancelablePromise<QueryResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/query',
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Search Trustgraph
     * Execute structured search in a Knowledge Core.
     *
     * Args:
     * req: Search request
     * org_id: Organization ID
     *
     * Returns:
     * Search results
     * @param requestBody
     * @param orgId
     * @returns apps__api__trustgraph_routes__SearchResponse Successful Response
     * @throws ApiError
     */
    public static searchTrustgraphApiV1TrustgraphSearchPost(
        requestBody: SearchRequest,
        orgId?: (string | null),
    ): CancelablePromise<apps__api__trustgraph_routes__SearchResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/search',
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Ingest Entity
     * Ingest an entity into a Knowledge Core.
     *
     * Args:
     * req: Ingestion request
     * org_id: Organization ID
     *
     * Returns:
     * Ingestion confirmation
     * @param requestBody
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestEntityApiV1TrustgraphIngestPost(
        requestBody: apps__api__trustgraph_routes__IngestRequest,
        orgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/ingest',
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Entity
     * Get entity details by ID.
     *
     * Args:
     * entity_id: Entity ID to retrieve
     *
     * Returns:
     * Entity with relationships
     * @param entityId
     * @returns EntityResponse Successful Response
     * @throws ApiError
     */
    public static getEntityApiV1TrustgraphEntitiesEntityIdGet(
        entityId: string,
    ): CancelablePromise<EntityResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/entities/{entity_id}',
            path: {
                'entity_id': entityId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Relationship
     * Create a relationship between entities.
     *
     * Args:
     * req: Relationship creation request
     *
     * Returns:
     * Relationship confirmation
     * @param requestBody
     * @returns RelateResponse Successful Response
     * @throws ApiError
     */
    public static createRelationshipApiV1TrustgraphRelatePost(
        requestBody: RelateRequest,
    ): CancelablePromise<RelateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/relate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Cores
     * List all Knowledge Cores with summary statistics.
     *
     * Returns:
     * List of cores with metadata and stats
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listCoresApiV1TrustgraphCoresGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/cores',
        });
    }
    /**
     * Get Core Stats
     * Get detailed statistics for a Knowledge Core.
     *
     * Args:
     * core_id: Knowledge Core ID (1-5)
     *
     * Returns:
     * Core metadata and statistics
     * @param coreId
     * @returns CoreResponse Successful Response
     * @throws ApiError
     */
    public static getCoreStatsApiV1TrustgraphCoresCoreIdStatsGet(
        coreId: number,
    ): CancelablePromise<CoreResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/cores/{core_id}/stats',
            path: {
                'core_id': coreId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Mcp Tools
     * List MCP tool definitions for integration with LLM agents.
     *
     * Returns:
     * List of MCP tool schemas
     * @returns ToolSchema Successful Response
     * @throws ApiError
     */
    public static listMcpToolsApiV1TrustgraphMcpToolsGet(): CancelablePromise<Array<ToolSchema>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/mcp/tools',
        });
    }
    /**
     * Get Audit Log
     * Get recent tool call audit logs.
     *
     * Args:
     * limit: Maximum records to return
     *
     * Returns:
     * List of audit records
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAuditLogApiV1TrustgraphAuditLogGet(
        limit: number = 100,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/audit/log',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
