/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__trivy_router__ScanImageRequest } from '../models/apps__api__trivy_router__ScanImageRequest';
import type { apps__api__trivy_router__ScanResponse } from '../models/apps__api__trivy_router__ScanResponse';
import type { apps__api__trivy_router__ScanSummaryResponse } from '../models/apps__api__trivy_router__ScanSummaryResponse';
import type { ScanFilesystemRequest } from '../models/ScanFilesystemRequest';
import type { ScanRepoRequest } from '../models/ScanRepoRequest';
import type { TrivyStatusResponse } from '../models/TrivyStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TrivyScannerService {
    /**
     * Scan a Docker image
     * Scan a Docker image for OS and library vulnerabilities using Trivy.
     *
     * Returns normalized findings ingested into the Brain Pipeline.
     * Falls back to mock data when trivy is not installed.
     * @param requestBody
     * @returns apps__api__trivy_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanImageApiV1ScanTrivyImagePost(
        requestBody: apps__api__trivy_router__ScanImageRequest,
    ): CancelablePromise<apps__api__trivy_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/trivy/image',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan a filesystem path
     * Scan a local filesystem path for vulnerabilities using Trivy.
     *
     * Falls back to mock data when trivy is not installed.
     * @param requestBody
     * @returns apps__api__trivy_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanFilesystemApiV1ScanTrivyFilesystemPost(
        requestBody: ScanFilesystemRequest,
    ): CancelablePromise<apps__api__trivy_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/trivy/filesystem',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan a git repository
     * Scan a remote git repository for vulnerabilities using Trivy.
     *
     * Falls back to mock data when trivy is not installed.
     * @param requestBody
     * @returns apps__api__trivy_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanRepoApiV1ScanTrivyRepoPost(
        requestBody: ScanRepoRequest,
    ): CancelablePromise<apps__api__trivy_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/scan/trivy/repo',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Check trivy availability
     * Return whether the trivy binary is available on this host.
     *
     * When trivy is not installed all scan endpoints return mock data.
     * @returns TrivyStatusResponse Successful Response
     * @throws ApiError
     */
    public static trivyStatusApiV1ScanTrivyStatusGet(): CancelablePromise<TrivyStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/trivy/status',
        });
    }
    /**
     * List scan history
     * Return the scan history for the given organisation, most recent first.
     *
     * Findings are omitted from the summary; re-run a scan to get full results.
     * @param orgId Organisation identifier
     * @returns apps__api__trivy_router__ScanSummaryResponse Successful Response
     * @throws ApiError
     */
    public static scanHistoryApiV1ScanTrivyHistoryGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__trivy_router__ScanSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/scan/trivy/history',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
