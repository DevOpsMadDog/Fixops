/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddIPRuleRequest } from '../models/AddIPRuleRequest';
import type { GatewayCheckRequest } from '../models/GatewayCheckRequest';
import type { ThrottlePolicyRequest } from '../models/ThrottlePolicyRequest';
import type { UpdateTierConfigRequest } from '../models/UpdateTierConfigRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ApiGatewayService {
    /**
     * Gateway Check
     * Full gateway security check for an incoming request.
     *
     * Performs in order:
     * 1. IP allowlist/blocklist check
     * 2. Rate limit check (sliding window per key + per IP)
     * 3. Request validation (content-type, payload size, required fields)
     * 4. API version tracking + deprecation alert
     *
     * Returns allowed=True or allowed=False with the reason and details from each check.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static gatewayCheckApiV1GatewayCheckPost(
        requestBody: GatewayCheckRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/gateway/check',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Rate Limits
     * Return current tier rate limit configurations.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRateLimitsApiV1GatewayRateLimitsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gateway/rate-limits',
        });
    }
    /**
     * Update Tier Config
     * Update the rate limit configuration for a plan tier.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateTierConfigApiV1GatewayRateLimitsTiersPut(
        requestBody: UpdateTierConfigRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/gateway/rate-limits/tiers',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Ip Rules
     * List all active IP allowlist/blocklist rules.
     * @param action Filter by action: 'allow' or 'block'
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listIpRulesApiV1GatewayIpRulesGet(
        action?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gateway/ip-rules',
            query: {
                'action': action,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Ip Rule
     * Add an IP allowlist or blocklist rule. Supports CIDR notation.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addIpRuleApiV1GatewayIpRulesPost(
        requestBody: AddIPRuleRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/gateway/ip-rules',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove Ip Rule
     * Soft-delete an IP rule by ID.
     * @param ruleId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static removeIpRuleApiV1GatewayIpRulesRuleIdDelete(
        ruleId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/gateway/ip-rules/{rule_id}',
            path: {
                'rule_id': ruleId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Set Throttle Policy
     * Set a custom throttle policy for a specific API key or IP.
     *
     * Overrides the plan tier defaults for that target. Use this to impose
     * stricter limits on abusive callers or grant higher limits to VIP keys.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static setThrottlePolicyApiV1GatewayThrottlePoliciesPost(
        requestBody: ThrottlePolicyRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/gateway/throttle-policies',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Analytics
     * Return API usage analytics summary:
     * - Per-endpoint stats (calls, error rate, latency percentiles)
     * - Top consumers by API key
     * - Error rate summary
     * - Overall latency percentiles
     * @param hours Lookback window in hours
     * @param limit Max results for top consumers
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAnalyticsApiV1GatewayAnalyticsGet(
        hours: number = 24,
        limit: number = 10,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gateway/analytics',
            query: {
                'hours': hours,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Version Stats
     * Return API version usage statistics and deprecation alerts.
     *
     * Shows which clients are still using deprecated API versions
     * and the distribution of usage across all supported versions.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getVersionStatsApiV1GatewayVersionStatsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gateway/version-stats',
        });
    }
    /**
     * Health
     * Health check for the API Gateway engine.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthApiV1GatewayHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/gateway/health',
        });
    }
}
