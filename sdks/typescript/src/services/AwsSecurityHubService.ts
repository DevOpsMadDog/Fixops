/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__aws_security_hub_router__ImportRequest } from '../models/apps__api__aws_security_hub_router__ImportRequest';
import type { apps__api__aws_security_hub_router__ImportResponse } from '../models/apps__api__aws_security_hub_router__ImportResponse';
import type { apps__api__aws_security_hub_router__ImportSummaryResponse } from '../models/apps__api__aws_security_hub_router__ImportSummaryResponse';
import type { AWSStatusResponse } from '../models/AWSStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AwsSecurityHubService {
    /**
     * Check AWS Security Hub configuration
     * Return whether AWS credentials are configured.
     *
     * When unconfigured all endpoints return mock data so the pipeline
     * can be exercised without real AWS credentials.
     * @returns AWSStatusResponse Successful Response
     * @throws ApiError
     */
    public static awsSecurityHubStatusApiV1ScanAwsSecurityHubStatusGet(): CancelablePromise<AWSStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/aws-security-hub/status',
        });
    }
    /**
     * Pull raw ASFF findings from Security Hub
     * Pull raw AWS Security Finding Format (ASFF) findings from Security Hub.
     *
     * Supports optional filtering by severity and workflow status.
     * Returns mock data when AWS credentials are not configured.
     * @param severity Filter by severity label: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
     * @param workflowStatus Filter by workflow status: NEW, NOTIFIED, RESOLVED, SUPPRESSED
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFindingsApiV1ScanAwsSecurityHubFindingsGet(
        severity?: (string | null),
        workflowStatus?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/aws-security-hub/findings',
            query: {
                'severity': severity,
                'workflow_status': workflowStatus,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Security Hub insights
     * Retrieve Security Hub insights.
     *
     * Returns mock data when AWS credentials are not configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getInsightsApiV1ScanAwsSecurityHubInsightsGet(): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/aws-security-hub/insights',
        });
    }
    /**
     * Get enabled compliance standards status
     * Retrieve enabled compliance standards (CIS, PCI DSS, AWS FSBP) and their
     * pass/fail control counts.
     *
     * Returns mock data when AWS credentials are not configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStandardsStatusApiV1ScanAwsSecurityHubStandardsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/aws-security-hub/standards',
        });
    }
    /**
     * Import Security Hub findings into ALDECI
     * Pull findings from AWS Security Hub, normalize from ASFF to UnifiedFinding
     * format, store in history, and ingest into the Brain Pipeline.
     *
     * Returns mock data when AWS credentials are not configured.
     * @param requestBody
     * @returns apps__api__aws_security_hub_router__ImportResponse Successful Response
     * @throws ApiError
     */
    public static importFindingsApiV1ScanAwsSecurityHubImportPost(
        requestBody: apps__api__aws_security_hub_router__ImportRequest,
    ): CancelablePromise<apps__api__aws_security_hub_router__ImportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/aws-security-hub/import',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Security Hub import history
     * Return the import history for the given organisation, most recent first.
     *
     * Findings are omitted from the summary; re-run an import to get full results.
     * @param orgId Organisation identifier
     * @returns apps__api__aws_security_hub_router__ImportSummaryResponse Successful Response
     * @throws ApiError
     */
    public static importHistoryApiV1ScanAwsSecurityHubHistoryGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__aws_security_hub_router__ImportSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/aws-security-hub/history',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
