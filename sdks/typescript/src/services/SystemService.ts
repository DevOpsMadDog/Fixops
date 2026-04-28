/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SystemService {
    /**
     * System information
     * Return system information and version details.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemInfoApiV1SystemInfoGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/info',
        });
    }
    /**
     * Non-sensitive configuration
     * Return non-sensitive configuration summary.
     *
     * Never exposes tokens, secrets, or credentials.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemConfigApiV1SystemConfigGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/config',
        });
    }
    /**
     * System metrics
     * Return system performance metrics for the Platform Admin (Hasan) persona.
     *
     * Includes uptime, memory, CPU, request counts, and database stats.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemMetricsApiV1SystemMetricsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/metrics',
        });
    }
    /**
     * System status overview
     * Return simplified system status for dashboards.
     *
     * Provides a quick UP/DOWN status with key indicators derived from real checks.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemStatusApiV1SystemStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/status',
        });
    }
    /**
     * Full deployment readiness assessment
     * Comprehensive readiness check -- the first thing a customer runs after deploy.
     *
     * Reports every integration, database, feed, and scanner with its status,
     * computes an overall readiness score (0-100), and provides actionable
     * recommendations for anything that is missing or degraded.
     *
     * **No authentication required.**  Secret values are NEVER exposed --
     * only whether the corresponding env var is set.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemReadinessApiV1SystemReadinessGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/readiness',
        });
    }
    /**
     * Guided onboarding wizard
     * Step-by-step onboarding wizard for new ALdeci deployments.
     *
     * Returns a checklist of setup steps with completion status, progress
     * percentage, and next recommended action. Designed for first-time
     * customers — deploy, hit this endpoint, follow the steps.
     *
     * **No authentication required** — first thing after deploy.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemOnboardingApiV1SystemOnboardingGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/onboarding',
        });
    }
    /**
     * Database health and size statistics
     * Return health and size information for all SQLite databases.
     *
     * Useful for monitoring disk usage, detecting growth, and planning
     * capacity (e.g. when to consider migrating to PostgreSQL).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dbStatsApiV1SystemDbStatsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/db-stats',
        });
    }
    /**
     * Recent distributed traces with timing
     * Return summaries of the last N completed distributed traces.
     *
     * Each entry includes trace_id, operation, service, span_count,
     * total_duration_ms, status, org_id, and engine_name (when set by engine calls).
     * Useful for diagnosing latency and correlating engine call paths to log entries.
     * @param limit Max traces to return
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemTracesRecentApiV1SystemTracesRecentGet(
        limit: number = 50,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/traces/recent',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Recent structured request logs
     * Return the last N structured request/response log entries from the in-memory ring buffer.
     *
     * Fields per entry: request_id, correlation_id, org_id, method, path,
     * status_code, duration_ms, req_size, resp_size, level, ts.
     *
     * Args:
     * limit: Number of entries to return (1-500, default 100).
     *
     * Returns:
     * JSON with ``logs`` list and ``count``.
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static systemLogsRecentApiV1SystemLogsRecentGet(
        limit: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/logs/recent',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Top-50 endpoint health snapshot
     * Return per-path health for the top 50 API prefixes.
     *
     * Derives status, avg_latency_ms, p95_latency_ms, error_rate, and
     * request_count from the in-memory request log ring buffer.
     * Returns static OK entries for prefixes with no recent traffic.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static endpointHealthApiV1SystemEndpointHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/endpoint-health',
        });
    }
}
