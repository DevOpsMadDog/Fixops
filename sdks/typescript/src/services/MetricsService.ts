/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MetricsService {
    /**
     * Prometheus metrics endpoint
     * Returns metrics in Prometheus text exposition format. Scrape with Prometheus or Grafana Agent. Pass ?org_id=<id> to scope metrics to a specific organisation.
     * @param orgId
     * @returns string Successful Response
     * @throws ApiError
     */
    public static prometheusMetricsApiV1MetricsPrometheusGet(
        orgId: string = 'default',
    ): CancelablePromise<string> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/prometheus',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * JSON metrics summary
     * Return key metrics as JSON — convenience endpoint for dashboards.
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static metricsSummaryApiV1MetricsSummaryGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/summary',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
