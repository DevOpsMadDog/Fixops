/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GateCheckRequest } from '../models/GateCheckRequest';
import type { GateCheckResponse } from '../models/GateCheckResponse';
import type { GateEvaluateRequest } from '../models/GateEvaluateRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class CiCdGateService {
    /**
     * Check Gate
     * Binary pass/fail for CI/CD pipelines.
     *
     * Accepts SARIF, SBOM, or pre-parsed findings. Runs through policy evaluation
     * and returns a structured verdict that CI systems consume as exit code.
     *
     * This is the primary endpoint that GitHub Actions / GitLab CI call.
     * @param requestBody
     * @returns GateCheckResponse Successful Response
     * @throws ApiError
     */
    public static checkGateApiV1GateCheckPost(
        requestBody: GateCheckRequest,
    ): CancelablePromise<GateCheckResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/gate/check',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Evaluate Findings
     * Evaluate a set of findings against configurable policies.
     *
     * Lighter than /check — no SARIF parsing, no material change analysis.
     * Just pure findings-vs-policy evaluation.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static evaluateFindingsApiV1GateEvaluatePost(
        requestBody: GateEvaluateRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/gate/evaluate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Gate Status
     * Get current gate configuration and health status.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static gateStatusApiV1GateStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gate/status',
        });
    }
    /**
     * Gate History
     * Get recent gate evaluations with optional filtering.
     * @param limit
     * @param repository
     * @param verdict
     * @returns any Successful Response
     * @throws ApiError
     */
    public static gateHistoryApiV1GateHistoryGet(
        limit: number = 20,
        repository?: (string | null),
        verdict?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gate/history',
            query: {
                'limit': limit,
                'repository': repository,
                'verdict': verdict,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Ci Setup
     * Get ready-to-use CI/CD configuration for a platform.
     *
     * Supported platforms: github-actions, gitlab-ci, azure-pipelines,
     * bitbucket-pipelines, jenkins.
     * @param platform
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCiSetupApiV1GateSetupPlatformGet(
        platform: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gate/setup/{platform}',
            path: {
                'platform': platform,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Ci Platforms
     * List all supported CI/CD platforms with setup availability.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listCiPlatformsApiV1GateSetupGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gate/setup',
        });
    }
}
