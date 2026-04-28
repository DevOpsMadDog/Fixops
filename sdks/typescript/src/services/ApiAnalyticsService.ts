/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RecordCallRequest } from '../models/RecordCallRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ApiAnalyticsService {
    /**
     * Record Call
     * Record a single API call.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static recordCallApiV1ApiAnalyticsCallsPost(
        requestBody: RecordCallRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/api-analytics/calls',
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
     * Endpoint Stats
     * Return call count, avg/p95 response time, and error rate for one endpoint.
     * @param endpoint
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static endpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet(
        endpoint: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/api-analytics/endpoints/{endpoint}/stats',
            path: {
                'endpoint': endpoint,
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
     * Top Endpoints
     * Return endpoints ranked by total call count.
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static topEndpointsApiV1ApiAnalyticsTopEndpointsGet(
        limit: number = 10,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/api-analytics/top-endpoints',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Slowest Endpoints
     * Return endpoints ranked by average response time (slowest first).
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static slowestEndpointsApiV1ApiAnalyticsSlowestEndpointsGet(
        limit: number = 10,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/api-analytics/slowest-endpoints',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Error Endpoints
     * Return endpoints with highest error rates.
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static errorEndpointsApiV1ApiAnalyticsErrorEndpointsGet(
        limit: number = 10,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/api-analytics/error-endpoints',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Usage Over Time
     * Return call counts bucketed by hour or day over the last N days.
     * @param bucket
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static usageOverTimeApiV1ApiAnalyticsUsageOverTimeGet(
        bucket: string = 'hour',
        days: number = 7,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/api-analytics/usage-over-time',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'bucket': bucket,
                'days': days,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
