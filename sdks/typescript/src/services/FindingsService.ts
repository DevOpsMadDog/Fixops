/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__findings_routes__BulkStatusUpdateRequest } from '../models/apps__api__findings_routes__BulkStatusUpdateRequest';
import type { apps__api__findings_routes__ExportRequest } from '../models/apps__api__findings_routes__ExportRequest';
import type { apps__api__findings_routes__FindingSummary } from '../models/apps__api__findings_routes__FindingSummary';
import type { apps__api__findings_routes__SLAStatus } from '../models/apps__api__findings_routes__SLAStatus';
import type { apps__api__findings_routes__StatusUpdateRequest } from '../models/apps__api__findings_routes__StatusUpdateRequest';
import type { apps__api__findings_routes__TimelineEvent } from '../models/apps__api__findings_routes__TimelineEvent';
import type { AssignmentRequest } from '../models/AssignmentRequest';
import type { BulkStatusUpdateResponse } from '../models/BulkStatusUpdateResponse';
import type { CommentResponse } from '../models/CommentResponse';
import type { FindingComment } from '../models/FindingComment';
import type { FindingDetailResponse } from '../models/FindingDetailResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class FindingsService {
    /**
     * Get Finding
     * Get complete finding detail with history.
     *
     * Args:
     * finding_id: Finding identifier
     *
     * Returns:
     * FindingDetailResponse with all details and history
     *
     * Raises:
     * HTTPException: 404 if finding not found or not accessible
     * @param findingId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns FindingDetailResponse Successful Response
     * @throws ApiError
     */
    public static getFindingApiV1FindingsFindingIdGet(
        findingId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<FindingDetailResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/findings/{finding_id}',
            path: {
                'finding_id': findingId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Finding Status
     * Update finding status.
     *
     * Args:
     * finding_id: Finding identifier
     * update: StatusUpdateRequest with new status
     *
     * Returns:
     * Updated finding metadata
     *
     * Raises:
     * HTTPException: 404 if finding not found, 400 if status invalid
     * @param findingId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateFindingStatusApiV1FindingsFindingIdStatusPut(
        findingId: string,
        requestBody: apps__api__findings_routes__StatusUpdateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/findings/{finding_id}/status',
            path: {
                'finding_id': findingId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Assign Finding
     * Assign finding to user or team.
     *
     * Args:
     * finding_id: Finding identifier
     * assignment: AssignmentRequest with user or team
     *
     * Returns:
     * Updated assignment info
     *
     * Raises:
     * HTTPException: 404 if finding not found, 400 if assignment invalid
     * @param findingId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static assignFindingApiV1FindingsFindingIdAssignPut(
        findingId: string,
        requestBody: AssignmentRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/findings/{finding_id}/assign',
            path: {
                'finding_id': findingId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Comment
     * Add comment to finding.
     *
     * Args:
     * finding_id: Finding identifier
     * comment: FindingComment with text
     *
     * Returns:
     * CommentResponse with comment details
     *
     * Raises:
     * HTTPException: 404 if finding not found
     * @param findingId
     * @param requestBody
     * @returns CommentResponse Successful Response
     * @throws ApiError
     */
    public static addCommentApiV1FindingsFindingIdCommentPost(
        findingId: string,
        requestBody: FindingComment,
    ): CancelablePromise<CommentResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/findings/{finding_id}/comment',
            path: {
                'finding_id': findingId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Finding Timeline
     * Get complete timeline of all actions on finding.
     *
     * Args:
     * finding_id: Finding identifier
     *
     * Returns:
     * List of timeline events in chronological order
     *
     * Raises:
     * HTTPException: 404 if finding not found
     * @param findingId
     * @returns apps__api__findings_routes__TimelineEvent Successful Response
     * @throws ApiError
     */
    public static getFindingTimelineApiV1FindingsFindingIdTimelineGet(
        findingId: string,
    ): CancelablePromise<Array<apps__api__findings_routes__TimelineEvent>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/findings/{finding_id}/timeline',
            path: {
                'finding_id': findingId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Findings Summary
     * Get executive summary of findings.
     *
     * Returns:
     * FindingSummary with key metrics and trends
     * @returns apps__api__findings_routes__FindingSummary Successful Response
     * @throws ApiError
     */
    public static getFindingsSummaryApiV1FindingsSummaryGet(): CancelablePromise<apps__api__findings_routes__FindingSummary> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/findings/summary',
        });
    }
    /**
     * Get Sla Status
     * Get SLA compliance for findings.
     *
     * Default SLAs (would be configurable):
     * - Critical: 1 day
     * - High: 3 days
     * - Medium: 7 days
     * - Low: 30 days
     *
     * Returns:
     * SLAStatus with compliance metrics
     * @returns apps__api__findings_routes__SLAStatus Successful Response
     * @throws ApiError
     */
    public static getSlaStatusApiV1FindingsSlaGet(): CancelablePromise<apps__api__findings_routes__SLAStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/findings/sla',
        });
    }
    /**
     * Bulk Update Status
     * Bulk update status for multiple findings.
     *
     * Args:
     * update: BulkStatusUpdateRequest with finding_ids and status
     *
     * Returns:
     * BulkStatusUpdateResponse with results
     *
     * Raises:
     * HTTPException: 400 if status invalid or too many findings
     * @param requestBody
     * @returns BulkStatusUpdateResponse Successful Response
     * @throws ApiError
     */
    public static bulkUpdateStatusApiV1FindingsBulkStatusPost(
        requestBody: apps__api__findings_routes__BulkStatusUpdateRequest,
    ): CancelablePromise<BulkStatusUpdateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/findings/bulk/status',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Findings
     * Export findings in JSON or CSV format.
     *
     * Args:
     * export_req: ExportRequest with format and filters
     *
     * Returns:
     * Download URL or file content
     *
     * Note:
     * In production, would stream response as StreamingResponse
     * @param requestBody
     * @returns string Successful Response
     * @throws ApiError
     */
    public static exportFindingsApiV1FindingsExportPost(
        requestBody: apps__api__findings_routes__ExportRequest,
    ): CancelablePromise<Record<string, string>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/findings/export',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
