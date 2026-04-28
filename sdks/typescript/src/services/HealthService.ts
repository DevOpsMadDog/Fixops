/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class HealthService {
    /**
     * Health Check
     * Liveness probe endpoint for Kubernetes.
     *
     * Returns 200 OK if the service is alive and can handle requests.
     * This endpoint should be lightweight and always return quickly.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthCheckApiV1HealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/health',
        });
    }
    /**
     * Readiness Check
     * Readiness probe endpoint for Kubernetes.
     *
     * Returns 200 OK if the service is ready to accept traffic.
     * Checks critical dependencies and returns 503 if any are unavailable.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static readinessCheckApiV1ReadyGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ready',
        });
    }
    /**
     * Metrics Endpoint
     * Return basic metrics in JSON format.
     *
     * For Prometheus metrics, use the /metrics endpoint exposed by OpenTelemetry.
     * This endpoint provides application-level metrics in JSON format.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static metricsEndpointApiV1MetricsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics',
        });
    }
    /**
     * Deep Health Check
     * Deep health check — verifies each subsystem individually.
     *
     * Checks:
     * - database:        SQLite SELECT 1 on the primary audit DB
     * - scanners:        importability of all 8 scanner engine modules
     * - brain_pipeline:  importability of core.brain_pipeline.BrainPipeline
     * - disk_space:      evidence storage directory free space (warn <1 GB)
     * - memory:          process RSS via /proc/self/status or psutil
     *
     * Returns HTTP 200 when all critical checks pass, 503 when any critical
     * check fails.  Scanner/memory checks are non-critical (degraded).
     *
     * No auth required — same as the liveness probe.  Do NOT put secrets in
     * this response.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deepHealthCheckApiV1HealthDeepGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/health/deep',
        });
    }
    /**
     * Database Health Check
     * Enterprise database health check.
     *
     * Reports connectivity and pool/file stats for the configured backend:
     * - PostgreSQL (production): SELECT 1 + pool stats (size, checked_in/out)
     * - SQLite (local dev / air-gap): SELECT 1 + file size + journal_mode
     *
     * Returns HTTP 200 when healthy, HTTP 503 when the database is unreachable.
     * Non-critical: a degraded database does NOT fail the liveness probe.
     *
     * No auth required (same as other health probes).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static databaseHealthCheckApiV1HealthDatabaseGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/health/database',
        });
    }
    /**
     * Legacy Health Check
     * Legacy health endpoint for backward-compatible probes.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static legacyHealthCheckHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/health',
        });
    }
}
