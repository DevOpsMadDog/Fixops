/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ObservabilityService {
    /**
     * Prometheus Metrics
     * Prometheus metrics endpoint.
     *
     * Exposes:
     * - fixops_http_requests_total{method, endpoint, status_code}
     * - fixops_http_request_duration_seconds{method, endpoint}
     * - fixops_active_connections
     * - fixops_pipeline_executions_total{status}
     * - fixops_pipeline_duration_seconds
     * - fixops_errors_total{error_type}
     *
     * Scrape with: ``prometheus.yml`` job ``scrape_configs[].static_configs.targets``
     * pointing at ``host:8000``, path ``/metrics``.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static prometheusMetricsMetricsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/metrics',
        });
    }
}
