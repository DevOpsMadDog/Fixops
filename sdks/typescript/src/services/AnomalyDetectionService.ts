/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AckResponse } from '../models/AckResponse';
import type { Anomaly } from '../models/Anomaly';
import type { AnomalyStats } from '../models/AnomalyStats';
import type { apps__api__anomaly_router__DetectRequest } from '../models/apps__api__anomaly_router__DetectRequest';
import type { apps__api__anomaly_router__DetectResponse } from '../models/apps__api__anomaly_router__DetectResponse';
import type { apps__api__anomaly_router__RecordMetricRequest } from '../models/apps__api__anomaly_router__RecordMetricRequest';
import type { BaselineStats } from '../models/BaselineStats';
import type { RecordMetricResponse } from '../models/RecordMetricResponse';
import type { SpikeDropRequest } from '../models/SpikeDropRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AnomalyDetectionService {
    /**
     * Record a metric data point
     * Store a time-series data point for the named metric.
     *
     * Returns the SQLite row ID of the inserted record.
     * @param requestBody
     * @returns RecordMetricResponse Successful Response
     * @throws ApiError
     */
    public static recordMetricApiV1AnomaliesMetricsPost(
        requestBody: apps__api__anomaly_router__RecordMetricRequest,
    ): CancelablePromise<RecordMetricResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomalies/metrics',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Run full anomaly scan
     * Scan all metrics for the given org and return detected anomalies.
     *
     * Runs spike, drop, drift, threshold-breach, and unusual-timing detection
     * for every distinct metric name recorded for the org.
     * @param requestBody
     * @returns apps__api__anomaly_router__DetectResponse Successful Response
     * @throws ApiError
     */
    public static detectAnomaliesApiV1AnomaliesDetectPost(
        requestBody: apps__api__anomaly_router__DetectRequest,
    ): CancelablePromise<apps__api__anomaly_router__DetectResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomalies/detect',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List detected anomalies
     * Retrieve persisted anomalies for the given org, optionally filtered by severity.
     * @param orgId Organisation ID
     * @param severity Filter by severity (low/medium/high/critical)
     * @param limit Max results
     * @returns Anomaly Successful Response
     * @throws ApiError
     */
    public static listAnomaliesApiV1AnomaliesGet(
        orgId: string = 'default',
        severity?: (string | null),
        limit: number = 100,
    ): CancelablePromise<Array<Anomaly>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomalies',
            query: {
                'org_id': orgId,
                'severity': severity,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Anomaly summary statistics
     * Return aggregate statistics: totals, breakdown by type/severity,
     * unacknowledged count, oldest/newest timestamps.
     * @param orgId Organisation ID
     * @returns AnomalyStats Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1AnomaliesStatsGet(
        orgId: string = 'default',
    ): CancelablePromise<AnomalyStats> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomalies/stats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Statistical baseline for a metric
     * Compute mean, std-dev, min, max over the lookback window for the metric.
     *
     * Returns 404 if there are fewer than 2 data points in the window.
     * @param metricName
     * @param orgId Organisation ID
     * @param windowDays Lookback window in days
     * @returns BaselineStats Successful Response
     * @throws ApiError
     */
    public static getBaselineApiV1AnomaliesBaselineMetricNameGet(
        metricName: string,
        orgId: string = 'default',
        windowDays: number = 30,
    ): CancelablePromise<BaselineStats> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomalies/baseline/{metric_name}',
            path: {
                'metric_name': metricName,
            },
            query: {
                'org_id': orgId,
                'window_days': windowDays,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Detect spike anomaly
     * Run spike detection on a single metric.
     *
     * A spike is flagged when the latest value exceeds the rolling mean
     * by more than threshold_pct percent.
     * @param requestBody
     * @returns apps__api__anomaly_router__DetectResponse Successful Response
     * @throws ApiError
     */
    public static detectSpikeApiV1AnomaliesDetectSpikePost(
        requestBody: SpikeDropRequest,
    ): CancelablePromise<apps__api__anomaly_router__DetectResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomalies/detect/spike',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Detect drop anomaly
     * Run drop detection on a single metric.
     *
     * A drop is flagged when the latest value is below the rolling mean
     * by more than threshold_pct percent.
     * @param requestBody
     * @returns apps__api__anomaly_router__DetectResponse Successful Response
     * @throws ApiError
     */
    public static detectDropApiV1AnomaliesDetectDropPost(
        requestBody: SpikeDropRequest,
    ): CancelablePromise<apps__api__anomaly_router__DetectResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomalies/detect/drop',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Acknowledge an anomaly
     * Mark an anomaly as reviewed.
     *
     * Returns 404 if the anomaly does not exist or was already acknowledged.
     * @param anomalyId
     * @returns AckResponse Successful Response
     * @throws ApiError
     */
    public static acknowledgeAnomalyApiV1AnomaliesAnomalyIdAckPost(
        anomalyId: string,
    ): CancelablePromise<AckResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomalies/{anomaly_id}/ack',
            path: {
                'anomaly_id': anomalyId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
