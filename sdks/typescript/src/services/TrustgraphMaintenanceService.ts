/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CoreHealthResponse } from '../models/CoreHealthResponse';
import type { FixRequest } from '../models/FixRequest';
import type { FixResponse } from '../models/FixResponse';
import type { MaintenanceIssueResponse } from '../models/MaintenanceIssueResponse';
import type { MaintenanceReportResponse } from '../models/MaintenanceReportResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TrustgraphMaintenanceService {
    /**
     * Run Maintenance Sweep
     * Run a full Knowledge Core integrity sweep across all 5 cores.
     *
     * Checks performed:
     * - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
     * - Orphaned entity detection (no relationships in any core)
     * - Duplicate finding detection (same source+rule+file in Core 2)
     * - Temporal staleness (entities not updated in >30 days)
     * - Missing required fields (severity in Core 2 findings)
     * - Entity type consistency (type matches core assignment)
     *
     * Returns:
     * MaintenanceReport with all issues found and summary stats.
     * @param orgId Organisation/tenant scope for the sweep
     * @returns MaintenanceReportResponse Successful Response
     * @throws ApiError
     */
    public static runMaintenanceSweepApiV1TrustgraphMaintenanceSweepPost(
        orgId: string = 'default',
    ): CancelablePromise<MaintenanceReportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/maintenance/sweep',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Core Health
     * Get health scores (0-100) for all 5 Knowledge Cores.
     *
     * Score penalises:
     * - Low entity connectivity (no relationships)
     * - High staleness (not updated in 30 days)
     * - Missing required fields (severity in Core 2)
     *
     * Returns:
     * Dict mapping core_id string to health details and score.
     * @returns CoreHealthResponse Successful Response
     * @throws ApiError
     */
    public static getCoreHealthApiV1TrustgraphMaintenanceHealthGet(): CancelablePromise<Record<string, CoreHealthResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/maintenance/health',
        });
    }
    /**
     * Auto Fix Issues
     * Auto-fix safe integrity issues detected in the Knowledge Cores.
     *
     * Fixable issue types:
     * - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
     * - duplicate: Soft-deletes all but the primary duplicate finding
     *
     * Args:
     * req: FixRequest with dry_run flag and optional issue_types filter.
     *
     * Returns:
     * FixResponse with counts of fixes applied, skipped, and errors.
     * @param requestBody
     * @returns FixResponse Successful Response
     * @throws ApiError
     */
    public static autoFixIssuesApiV1TrustgraphMaintenanceFixPost(
        requestBody: FixRequest,
    ): CancelablePromise<FixResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/trustgraph/maintenance/fix',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Current Issues
     * Run a maintenance sweep and return the detected issues with optional filters.
     *
     * Args:
     * severity: Filter to a specific severity level.
     * issue_type: Filter to a specific issue type.
     * core_id: Filter to issues in a specific Knowledge Core.
     * limit: Maximum number of issues to return.
     *
     * Returns:
     * List of MaintenanceIssue dicts, ordered by severity (critical first).
     * @param severity Filter by severity: critical | high | medium | low
     * @param issueType Filter by issue type: contradiction | orphan | duplicate | stale | missing_field | type_mismatch
     * @param coreId Filter by Knowledge Core ID (1-5). 0 = cross-core.
     * @param limit Maximum issues to return
     * @returns MaintenanceIssueResponse Successful Response
     * @throws ApiError
     */
    public static getCurrentIssuesApiV1TrustgraphMaintenanceIssuesGet(
        severity?: (string | null),
        issueType?: (string | null),
        coreId?: (number | null),
        limit: number = 100,
    ): CancelablePromise<Array<MaintenanceIssueResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/trustgraph/maintenance/issues',
            query: {
                'severity': severity,
                'issue_type': issueType,
                'core_id': coreId,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
