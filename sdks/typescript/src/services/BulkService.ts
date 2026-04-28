/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__bulk_router__BulkAssignRequest } from '../models/apps__api__bulk_router__BulkAssignRequest';
import type { apps__api__bulk_router__BulkStatusUpdateRequest } from '../models/apps__api__bulk_router__BulkStatusUpdateRequest';
import type { apps__api__bulk_router__JobStatusResponse } from '../models/apps__api__bulk_router__JobStatusResponse';
import type { BulkAcceptRiskRequest } from '../models/BulkAcceptRiskRequest';
import type { BulkApplyPoliciesRequest } from '../models/BulkApplyPoliciesRequest';
import type { BulkCreateTicketsRequest } from '../models/BulkCreateTicketsRequest';
import type { BulkDeleteRequest } from '../models/BulkDeleteRequest';
import type { BulkOperationResponse } from '../models/BulkOperationResponse';
import type { BulkUpdateRequest } from '../models/BulkUpdateRequest';
import type { JobResponse } from '../models/JobResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class BulkService {
    /**
     * Bulk Update Cluster Status
     * Bulk update cluster status.
     * @param requestBody
     * @returns JobResponse Successful Response
     * @throws ApiError
     */
    public static bulkUpdateClusterStatusApiV1BulkClustersStatusPost(
        requestBody: apps__api__bulk_router__BulkStatusUpdateRequest,
    ): CancelablePromise<JobResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/clusters/status',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Assign Clusters
     * Bulk assign clusters to a user.
     * @param requestBody
     * @returns JobResponse Successful Response
     * @throws ApiError
     */
    public static bulkAssignClustersApiV1BulkClustersAssignPost(
        requestBody: apps__api__bulk_router__BulkAssignRequest,
    ): CancelablePromise<JobResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/clusters/assign',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Accept Risk
     * Bulk accept risk for clusters.
     * @param requestBody
     * @returns JobResponse Successful Response
     * @throws ApiError
     */
    public static bulkAcceptRiskApiV1BulkClustersAcceptRiskPost(
        requestBody: BulkAcceptRiskRequest,
    ): CancelablePromise<JobResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/clusters/accept-risk',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Create Tickets
     * Bulk create tickets for clusters.
     * @param requestBody
     * @returns JobResponse Successful Response
     * @throws ApiError
     */
    public static bulkCreateTicketsApiV1BulkClustersCreateTicketsPost(
        requestBody: BulkCreateTicketsRequest,
    ): CancelablePromise<JobResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/clusters/create-tickets',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Download Export
     * Download an export file produced by /export.
     * @param filename
     * @returns any Successful Response
     * @throws ApiError
     */
    public static downloadExportApiV1BulkExportsFilenameGet(
        filename: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/bulk/exports/{filename}',
            path: {
                'filename': filename,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Job Status
     * Get status of a bulk job.
     * @param jobId
     * @returns apps__api__bulk_router__JobStatusResponse Successful Response
     * @throws ApiError
     */
    public static getJobStatusApiV1BulkJobsJobIdGet(
        jobId: string,
    ): CancelablePromise<apps__api__bulk_router__JobStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/bulk/jobs/{job_id}',
            path: {
                'job_id': jobId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Cancel Job
     * Cancel a pending or in-progress job.
     * @param jobId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static cancelJobApiV1BulkJobsJobIdDelete(
        jobId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/bulk/jobs/{job_id}',
            path: {
                'job_id': jobId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Jobs
     * List bulk jobs with optional filters.
     * @param status
     * @param actionType
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listJobsApiV1BulkJobsGet(
        status?: (string | null),
        actionType?: (string | null),
        limit: number = 20,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/bulk/jobs',
            query: {
                'status': status,
                'action_type': actionType,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Update Findings
     * Bulk update findings in AnalyticsDB.
     *
     * Supported update fields: status, metadata (merged).
     * @param requestBody
     * @returns BulkOperationResponse Successful Response
     * @throws ApiError
     */
    public static bulkUpdateFindingsApiV1BulkFindingsUpdatePost(
        requestBody: BulkUpdateRequest,
    ): CancelablePromise<BulkOperationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/findings/update',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Delete Findings
     * Bulk delete findings from AnalyticsDB.
     * @param requestBody
     * @returns BulkOperationResponse Successful Response
     * @throws ApiError
     */
    public static bulkDeleteFindingsApiV1BulkFindingsDeletePost(
        requestBody: BulkDeleteRequest,
    ): CancelablePromise<BulkOperationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/findings/delete',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Assign Findings
     * Bulk assign findings to a user via AnalyticsDB metadata update.
     * @param requestBody
     * @returns BulkOperationResponse Successful Response
     * @throws ApiError
     */
    public static bulkAssignFindingsApiV1BulkFindingsAssignPost(
        requestBody: apps__api__bulk_router__BulkAssignRequest,
    ): CancelablePromise<BulkOperationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/findings/assign',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Apply Policies
     * Bulk apply policies to target findings.
     *
     * For each (policy, finding) pair the policy rules are evaluated and the
     * result is stored in the finding's metadata under ``applied_policies``.
     * @param requestBody
     * @returns BulkOperationResponse Successful Response
     * @throws ApiError
     */
    public static bulkApplyPoliciesApiV1BulkPoliciesApplyPost(
        requestBody: BulkApplyPoliciesRequest,
    ): CancelablePromise<BulkOperationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/policies/apply',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Bulk Status
     * Bulk operations status — running jobs, completed, failed.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static bulkStatusApiV1BulkStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/bulk/status',
        });
    }
}
