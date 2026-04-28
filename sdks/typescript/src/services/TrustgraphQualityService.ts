/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BackfillRequest } from '../models/BackfillRequest';
import type { BackfillResponse } from '../models/BackfillResponse';
import type { CoverageReportResponse } from '../models/CoverageReportResponse';
import type { GraphStatsResponse } from '../models/GraphStatsResponse';
import type { QualityIssueResponse } from '../models/QualityIssueResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TrustgraphQualityService {
    /**
     * Get Coverage Report
     * Get TrustGraph coverage report — what % of ALDECI data is indexed per core.
     *
     * Returns:
     * Per-core coverage percentages, entity counts, and orphaned entity counts.
     * @returns CoverageReportResponse Successful Response
     * @throws ApiError
     */
    public static getCoverageReportApiV1TrustgraphQualityCoverageGet(): CancelablePromise<CoverageReportResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/quality/coverage',
        });
    }
    /**
     * Get Orphaned Findings
     * Find security findings (Core 2) not connected to any other TrustGraph entity.
     *
     * Args:
     * include_assets: If true, also returns disconnected assets from Core 1.
     *
     * Returns:
     * List of orphaned entity dicts.
     * @param includeAssets Also include disconnected assets from Core 1
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getOrphanedFindingsApiV1TrustgraphQualityOrphansGet(
        includeAssets: boolean = false,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/quality/orphans',
            query: {
                'include_assets': includeAssets,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Backfill Missing Data
     * Index orphaned findings and disconnected assets into TrustGraph.
     *
     * Args:
     * req: BackfillRequest with dry_run flag.
     *
     * Returns:
     * BackfillReport with counts of what was (or would be) indexed.
     * @param requestBody
     * @returns BackfillResponse Successful Response
     * @throws ApiError
     */
    public static backfillMissingDataApiV1TrustgraphQualityBackfillPost(
        requestBody: BackfillRequest,
    ): CancelablePromise<BackfillResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/quality/backfill',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Graph Stats
     * Get high-level TrustGraph statistics: entity counts, relationship counts, coverage %.
     *
     * Returns:
     * GraphStats summary across all Knowledge Cores.
     * @returns GraphStatsResponse Successful Response
     * @throws ApiError
     */
    public static getGraphStatsApiV1TrustgraphQualityStatsGet(): CancelablePromise<GraphStatsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/quality/stats',
        });
    }
    /**
     * Get Quality Issues
     * Run TrustGraph quality checks and return all detected issues.
     *
     * Checks performed:
     * - Findings without severity
     * - Assets without classification
     * - Duplicate findings (same source+rule+file)
     * - Stale entities (not updated in 30 days)
     * - Disconnected subgraphs (entities with no relationships)
     *
     * Returns:
     * List of QualityIssue dicts, ordered by severity (critical -> low).
     * @returns QualityIssueResponse Successful Response
     * @throws ApiError
     */
    public static getQualityIssuesApiV1TrustgraphQualityIssuesGet(): CancelablePromise<Array<QualityIssueResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/quality/issues',
        });
    }
}
