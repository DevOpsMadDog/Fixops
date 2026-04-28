/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__snyk_router__ImportRequest } from '../models/apps__api__snyk_router__ImportRequest';
import type { apps__api__snyk_router__ImportResponse } from '../models/apps__api__snyk_router__ImportResponse';
import type { apps__api__snyk_router__ImportSummaryResponse } from '../models/apps__api__snyk_router__ImportSummaryResponse';
import type { SnykStatusResponse } from '../models/SnykStatusResponse';
import type { TestPackageRequest } from '../models/TestPackageRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SnykScannerService {
    /**
     * Check Snyk API configuration
     * Return whether the Snyk API token is configured.
     *
     * When unconfigured all endpoints return mock data so the pipeline
     * can be exercised without real credentials.
     * @returns SnykStatusResponse Successful Response
     * @throws ApiError
     */
    public static snykStatusApiV1ScanSnykStatusGet(): CancelablePromise<SnykStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/snyk/status',
        });
    }
    /**
     * List Snyk projects
     * List all projects monitored by Snyk for the configured org.
     *
     * Returns mock project data when SNYK_API_TOKEN is not configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listProjectsApiV1ScanSnykProjectsGet(): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/snyk/projects',
        });
    }
    /**
     * Get issues for a Snyk project
     * Get all open issues for a specific Snyk project.
     *
     * Returns mock issue data when SNYK_API_TOKEN is not configured.
     * @param projectId Snyk project UUID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getProjectIssuesApiV1ScanSnykIssuesGet(
        projectId: string,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/snyk/issues',
            query: {
                'project_id': projectId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Test a single package for vulnerabilities
     * Test a single package version against Snyk's vulnerability database.
     *
     * Returns mock data when SNYK_API_TOKEN is not configured.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testPackageApiV1ScanSnykTestPackagePost(
        requestBody: TestPackageRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/snyk/test-package',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Import all Snyk issues for an org
     * Pull all issues from Snyk for the given org, normalize them via
     * SnykNormalizer, and ingest into the Brain Pipeline.
     *
     * Returns mock data when SNYK_API_TOKEN is not configured.
     * @param requestBody
     * @returns apps__api__snyk_router__ImportResponse Successful Response
     * @throws ApiError
     */
    public static importResultsApiV1ScanSnykImportPost(
        requestBody: apps__api__snyk_router__ImportRequest,
    ): CancelablePromise<apps__api__snyk_router__ImportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/snyk/import',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Snyk import history
     * Return the import history for the given organisation, most recent first.
     *
     * Findings are omitted from the summary; re-run an import to get full results.
     * @param orgId Organisation identifier
     * @returns apps__api__snyk_router__ImportSummaryResponse Successful Response
     * @throws ApiError
     */
    public static importHistoryApiV1ScanSnykHistoryGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__snyk_router__ImportSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/snyk/history',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
