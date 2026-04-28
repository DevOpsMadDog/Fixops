/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ArchitectureDetectRequest } from '../models/ArchitectureDetectRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveAGraphArchitectureService {
    /**
     * Detect architecture (layers/services/databases/APIs) from a repo
     * Run architecture detection over a repository and persist the snapshot.
     *
     * Wires to existing helpers when available:
     * * ``core.security_architecture_review_engine`` — high-level review
     * * Filesystem walk for layer / database / API detection (deterministic)
     *
     * Returns: report_id, layer count, service count, database count, API count.
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphArchitectureDetectApiV1GraphArchitectureDetectPost(
        requestBody: ArchitectureDetectRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/graph/architecture-detect',
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
     * Return inbound + outbound data flows for a service
     * Return data flows centred on the given service.
     *
     * Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
     * deterministic empty-graph response so callers can hook this into UI without
     * a 500 when a tenant has no graph yet.
     * @param serviceId
     * @param depth
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphFlowsApiV1GraphFlowsServiceIdGet(
        serviceId: string,
        depth: number = 2,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/flows/{service_id}',
            path: {
                'service_id': serviceId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'depth': depth,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Return architectural layer assignment for a module
     * Return the layer (presentation/application/domain/infra/shared) for a module.
     *
     * Searches recent ``architecture_reports`` persisted by /architecture-detect
     * and returns the first match. If no report exists, returns 'unclassified'.
     * @param moduleId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphLayersApiV1GraphLayersModuleIdGet(
        moduleId: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/layers/{module_id}',
            path: {
                'module_id': moduleId,
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
     * List databases referenced by a repository
     * Return databases discovered by /architecture-detect for the given repo.
     * @param repoId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphDatabasesApiV1GraphDatabasesRepoIdGet(
        repoId: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/databases/{repo_id}',
            path: {
                'repo_id': repoId,
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
     * Diff architecture graph between two snapshots / a PR
     * Compare two architecture snapshots and return added/removed entities.
     *
     * Snapshots are looked up by ``base_report_id`` / ``head_report_id`` query
     * params, or by PR id if the snapshots are tagged with ``pr_id``.
     * @param prId
     * @param baseReportId
     * @param headReportId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphDiffApiV1GraphDiffGet(
        prId?: (string | null),
        baseReportId?: (string | null),
        headReportId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/diff',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'prId': prId,
                'base_report_id': baseReportId,
                'head_report_id': headReportId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List graph nodes whose state changed since a given timestamp
     * Return graph nodes added/modified after the supplied threshold.
     *
     * Sources, in priority:
     * 1. ``core.cloud_graph.CloudGraphEngine`` (live tenant graph)
     * 2. ``architecture_reports`` persistent_store snapshots (delta of new nodes)
     *
     * Both sources fall through gracefully — if neither has data we return an
     * empty list with `available=False` so the UI can render an EmptyState.
     * @param since ISO-8601 timestamp or relative duration (e.g. 4h, 2d)
     * @param nodeKinds Comma-separated kinds filter: service,layer,database,api
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphAffectedNodesApiV1GraphAffectedNodesGet(
        since: string,
        nodeKinds?: (string | null),
        limit: number = 500,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/affected-nodes',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'since': since,
                'node_kinds': nodeKinds,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Diff two architecture/graph snapshots by their IDs
     * Diff two architecture-detect snapshots by ID.
     *
     * Looks both snapshots up in the ``architecture_reports`` persistent store and
     * returns added/removed entities across layers, services, databases and APIs.
     *
     * Wires to ``core.architecture_diff_engine.ArchitectureDiffEngine`` if it
     * exists; falls back to a deterministic set diff otherwise.
     * @param baselineId
     * @param currentId
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static graphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet(
        baselineId: string,
        currentId: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/graph/diff/{baseline_id}/{current_id}',
            path: {
                'baseline_id': baselineId,
                'current_id': currentId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
