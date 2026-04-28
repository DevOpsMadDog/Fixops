/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ContinuousMonitoringModel } from '../models/ContinuousMonitoringModel';
import type { CreatePenTestConfigModel } from '../models/CreatePenTestConfigModel';
import type { CreatePenTestRequestModel } from '../models/CreatePenTestRequestModel';
import type { CreatePenTestResultModel } from '../models/CreatePenTestResultModel';
import type { UpdatePenTestConfigModel } from '../models/UpdatePenTestConfigModel';
import type { UpdatePenTestRequestModel } from '../models/UpdatePenTestRequestModel';
import type { VerifyVulnerabilityModel } from '../models/VerifyVulnerabilityModel';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MpteService {
    /**
     * Mpte Health
     * MPTE verification engine health check.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static mpteHealthApiV1MpteHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/health',
        });
    }
    /**
     * Mpte Status
     * MPTE verification engine status.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static mpteStatusApiV1MpteStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/status',
        });
    }
    /**
     * List Pen Test Requests
     * List pen test requests, scoped to the caller's org.
     * @param findingId
     * @param status
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPenTestRequestsApiV1MpteRequestsGet(
        findingId?: (string | null),
        status?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/requests',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'finding_id': findingId,
                'status': status,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Pen Test Request
     * Create a new pen test request with automated testing.
     *
     * Creates the request immediately and runs verification in the background.
     * If the external MPTE service is unreachable, falls back to the local
     * micro-pentest engine (cve_tester + real_scanner).
     *
     * Security: Validates target_url for SSRF, enforces concurrent scan limit.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPenTestRequestApiV1MpteRequestsPost(
        requestBody: CreatePenTestRequestModel,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/requests',
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
     * Get Pen Test Request
     * Get a pen test request by ID.
     * @param requestId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPenTestRequestApiV1MpteRequestsRequestIdGet(
        requestId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/requests/{request_id}',
            path: {
                'request_id': requestId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Pen Test Request
     * Update a pen test request.
     * @param requestId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updatePenTestRequestApiV1MpteRequestsRequestIdPut(
        requestId: string,
        requestBody: UpdatePenTestRequestModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/mpte/requests/{request_id}',
            path: {
                'request_id': requestId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Start Pen Test
     * Start a pen test.
     * @param requestId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static startPenTestApiV1MpteRequestsRequestIdStartPost(
        requestId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/requests/{request_id}/start',
            path: {
                'request_id': requestId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Cancel Pen Test
     * Cancel a pen test.
     * @param requestId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static cancelPenTestApiV1MpteRequestsRequestIdCancelPost(
        requestId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/requests/{request_id}/cancel',
            path: {
                'request_id': requestId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Pen Test Results
     * List pen test results for the caller's org, including real scan results.
     * @param findingId
     * @param exploitability
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPenTestResultsApiV1MpteResultsGet(
        findingId?: (string | null),
        exploitability?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/results',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'finding_id': findingId,
                'exploitability': exploitability,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Pen Test Result
     * Create a new pen test result.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPenTestResultApiV1MpteResultsPost(
        requestBody: CreatePenTestResultModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/results',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Pen Test Result By Request
     * Get pen test result by request ID.
     * @param requestId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPenTestResultByRequestApiV1MpteResultsByRequestRequestIdGet(
        requestId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/results/by-request/{request_id}',
            path: {
                'request_id': requestId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Pen Test Configs
     * List MPTE configurations.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPenTestConfigsApiV1MpteConfigsGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/configs',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Pen Test Config
     * Create a new MPTE configuration.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPenTestConfigApiV1MpteConfigsPost(
        requestBody: CreatePenTestConfigModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/configs',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Pen Test Config
     * Get MPTE configuration by ID.
     * @param configId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPenTestConfigApiV1MpteConfigsConfigIdGet(
        configId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/configs/{config_id}',
            path: {
                'config_id': configId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Pen Test Config
     * Update MPTE configuration.
     * @param configId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updatePenTestConfigApiV1MpteConfigsConfigIdPut(
        configId: string,
        requestBody: UpdatePenTestConfigModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/mpte/configs/{config_id}',
            path: {
                'config_id': configId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete Pen Test Config
     * Delete MPTE configuration.
     * @param configId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deletePenTestConfigApiV1MpteConfigsConfigIdDelete(
        configId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/mpte/configs/{config_id}',
            path: {
                'config_id': configId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Verify Vulnerability
     * Verify a vulnerability by attempting exploitation.
     *
     * Similar to Akido Security's automated verification.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyVulnerabilityApiV1MpteVerifyPost(
        requestBody: VerifyVulnerabilityModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/verify',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Setup Continuous Monitoring
     * Set up continuous security monitoring.
     *
     * Similar to Prism Security's continuous scanning.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static setupContinuousMonitoringApiV1MpteMonitoringPost(
        requestBody: ContinuousMonitoringModel,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mpte/monitoring',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
