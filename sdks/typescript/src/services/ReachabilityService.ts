/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BulkAnalysisRequest } from '../models/BulkAnalysisRequest';
import type { BulkAnalysisResponse } from '../models/BulkAnalysisResponse';
import type { ReachabilityAnalysisRequest } from '../models/ReachabilityAnalysisRequest';
import type { ReachabilityAnalysisResponse } from '../models/ReachabilityAnalysisResponse';
import type { risk__reachability__api__CallGraphRequest } from '../models/risk__reachability__api__CallGraphRequest';
import type { risk__reachability__api__JobStatusResponse } from '../models/risk__reachability__api__JobStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ReachabilityService {
    /**
     * Analyze Reachability
     * Analyze vulnerability reachability in a Git repository.
     *
     * This endpoint performs comprehensive reachability analysis combining
     * design-time and runtime analysis to determine if a vulnerability is
     * actually exploitable in the codebase.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns ReachabilityAnalysisResponse Successful Response
     * @throws ApiError
     */
    public static analyzeReachabilityApiV1ReachabilityAnalyzePost(
        requestBody: ReachabilityAnalysisRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<ReachabilityAnalysisResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reachability/analyze',
            headers: {
                'X-Org-ID': xOrgId,
            },
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
     * Analyze Bulk
     * Analyze multiple vulnerabilities in bulk.
     *
     * This endpoint queues multiple reachability analyses for efficient
     * batch processing.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns BulkAnalysisResponse Successful Response
     * @throws ApiError
     */
    public static analyzeBulkApiV1ReachabilityAnalyzeBulkPost(
        requestBody: BulkAnalysisRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<BulkAnalysisResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reachability/analyze/bulk',
            headers: {
                'X-Org-ID': xOrgId,
            },
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
     * Get Job Status
     * Get status of an analysis job.
     * @param jobId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns risk__reachability__api__JobStatusResponse Successful Response
     * @throws ApiError
     */
    public static getJobStatusApiV1ReachabilityJobJobIdGet(
        jobId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<risk__reachability__api__JobStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/job/{job_id}',
            path: {
                'job_id': jobId,
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
     * Get Result
     * Get cached analysis result.
     * @param cveId
     * @param componentName
     * @param componentVersion
     * @param repoUrl
     * @param repoCommit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getResultApiV1ReachabilityResultsCveIdGet(
        cveId: string,
        componentName: string,
        componentVersion: string,
        repoUrl: string,
        repoCommit?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/results/{cve_id}',
            path: {
                'cve_id': cveId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'component_name': componentName,
                'component_version': componentVersion,
                'repo_url': repoUrl,
                'repo_commit': repoCommit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete Result
     * Delete cached analysis result.
     * @param cveId
     * @param componentName
     * @param componentVersion
     * @param repoUrl
     * @param repoCommit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deleteResultApiV1ReachabilityResultsCveIdDelete(
        cveId: string,
        componentName: string,
        componentVersion: string,
        repoUrl: string,
        repoCommit?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/reachability/results/{cve_id}',
            path: {
                'cve_id': cveId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'component_name': componentName,
                'component_version': componentVersion,
                'repo_url': repoUrl,
                'repo_commit': repoCommit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Health Check
     * Health check endpoint.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthCheckApiV1ReachabilityHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/health',
        });
    }
    /**
     * Get Metrics
     * Get analysis metrics.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMetricsApiV1ReachabilityMetricsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/metrics',
        });
    }
    /**
     * Get Analysis
     * Get reachability analysis results (GET alias for /analyze POST).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAnalysisApiV1ReachabilityAnalysisGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reachability/analysis',
        });
    }
    /**
     * Analyze Call Graph
     * Build and return call graph statistics for a repository.
     *
     * Supports Python, JavaScript/TypeScript, Java, and Go.
     * Returns graph stats, entry points, and optional reachability check.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyzeCallGraphApiV1ReachabilityCallGraphPost(
        requestBody: risk__reachability__api__CallGraphRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/reachability/call-graph',
            headers: {
                'X-Org-ID': xOrgId,
            },
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
}
