/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingVerifyRequest } from '../models/FindingVerifyRequest';
import type { PoCRequest } from '../models/PoCRequest';
import type { ReachabilityProbeRequest } from '../models/ReachabilityProbeRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SandboxVerificationService {
    /**
     * Run Poc Verification
     * Execute a PoC script in Docker sandbox and return verification result.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runPocVerificationApiV1SandboxVerifyPost(
        requestBody: PoCRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sandbox/verify',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Verify Finding
     * Auto-generate and execute a PoC based on finding CVE/CWE.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyFindingApiV1SandboxVerifyFindingPost(
        requestBody: FindingVerifyRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sandbox/verify-finding',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Results
     * Return all verification results from this session.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getResultsApiV1SandboxResultsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sandbox/results',
        });
    }
    /**
     * Get Stats
     * Return sandbox verification statistics.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1SandboxStatsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sandbox/stats',
        });
    }
    /**
     * Sandbox Health
     * Check Docker sandbox availability.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sandboxHealthApiV1SandboxHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sandbox/health',
        });
    }
    /**
     * Sandbox Status
     * Status alias for Docker sandbox (mirrors /health).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sandboxStatusApiV1SandboxStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sandbox/status',
        });
    }
    /**
     * Sandboxed Reachability
     * Run reachability probes inside Docker sandbox.
     *
     * Instead of probing from the host (SSRF risk), all network checks
     * run in ephemeral Docker containers with resource limits.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sandboxedReachabilityApiV1SandboxReachabilityPost(
        requestBody: ReachabilityProbeRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sandbox/reachability',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sandboxed Reachability Single
     * Probe a single target URL from Docker sandbox.
     * @param target
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sandboxedReachabilitySingleApiV1SandboxReachabilitySinglePost(
        target: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sandbox/reachability/single',
            query: {
                'target': target,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
