/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__azure_defender_router__ImportRequest } from '../models/apps__api__azure_defender_router__ImportRequest';
import type { apps__api__azure_defender_router__ImportResponse } from '../models/apps__api__azure_defender_router__ImportResponse';
import type { apps__api__azure_defender_router__ImportSummaryResponse } from '../models/apps__api__azure_defender_router__ImportSummaryResponse';
import type { AzureStatusResponse } from '../models/AzureStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AzureDefenderService {
    /**
     * Check Azure Defender configuration
     * Return whether Azure credentials are configured.
     *
     * When unconfigured all endpoints return mock data so the pipeline
     * can be exercised without real Azure credentials.
     * @returns AzureStatusResponse Successful Response
     * @throws ApiError
     */
    public static azureDefenderStatusApiV1ScanAzureDefenderStatusGet(): CancelablePromise<AzureStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/azure-defender/status',
        });
    }
    /**
     * Pull security alerts from Microsoft Defender for Cloud
     * Pull security alerts from Microsoft Defender for Cloud.
     *
     * Supports optional filtering by severity.
     * Returns mock data when Azure credentials are not configured.
     * @param severity Filter by severity: Critical, High, Medium, Low
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAlertsApiV1ScanAzureDefenderAlertsGet(
        severity?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/azure-defender/alerts',
            query: {
                'severity': severity,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Azure Secure Score
     * Retrieve the Azure Secure Score for the configured subscription.
     *
     * Returns mock data when Azure credentials are not configured.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSecureScoreApiV1ScanAzureDefenderSecureScoreGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/azure-defender/secure-score',
        });
    }
    /**
     * Get security recommendations from Microsoft Defender for Cloud
     * Retrieve security recommendations from Microsoft Defender for Cloud.
     *
     * Supports optional filtering by category.
     * Returns mock data when Azure credentials are not configured.
     * @param category Filter by category: IdentityAndAccess, Compute, Data, Networking
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRecommendationsApiV1ScanAzureDefenderRecommendationsGet(
        category?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/azure-defender/recommendations',
            query: {
                'category': category,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Import Azure Defender findings into ALDECI
     * Pull alerts from Microsoft Defender for Cloud, normalize to UnifiedFinding
     * format, store in history, and ingest into the Brain Pipeline.
     *
     * Returns mock data when Azure credentials are not configured.
     * @param requestBody
     * @returns apps__api__azure_defender_router__ImportResponse Successful Response
     * @throws ApiError
     */
    public static importFindingsApiV1ScanAzureDefenderImportPost(
        requestBody: apps__api__azure_defender_router__ImportRequest,
    ): CancelablePromise<apps__api__azure_defender_router__ImportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/azure-defender/import',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Azure Defender import history
     * Return the import history for the given organisation, most recent first.
     *
     * Findings are omitted from the summary; re-run an import to get full results.
     * @param orgId Organisation identifier
     * @returns apps__api__azure_defender_router__ImportSummaryResponse Successful Response
     * @throws ApiError
     */
    public static importHistoryApiV1ScanAzureDefenderHistoryGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__azure_defender_router__ImportSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/azure-defender/history',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
