/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AlertGroupResponse } from '../models/AlertGroupResponse';
import type { apps__api__anomaly_ml_router__AnomalyListResponse } from '../models/apps__api__anomaly_ml_router__AnomalyListResponse';
import type { apps__api__anomaly_ml_router__FeedbackResponse } from '../models/apps__api__anomaly_ml_router__FeedbackResponse';
import type { apps__api__anomaly_ml_router__RecordEventRequest } from '../models/apps__api__anomaly_ml_router__RecordEventRequest';
import type { core__anomaly_ml_engine__FeedbackRequest } from '../models/core__anomaly_ml_engine__FeedbackRequest';
import type { IsolationRequest } from '../models/IsolationRequest';
import type { IsolationResponse } from '../models/IsolationResponse';
import type { RecordEventResponse } from '../models/RecordEventResponse';
import type { TimeSeriesRequest } from '../models/TimeSeriesRequest';
import type { TimeSeriesResponse } from '../models/TimeSeriesResponse';
import type { UEBARiskResponse } from '../models/UEBARiskResponse';
import type { ZScoreRequest } from '../models/ZScoreRequest';
import type { ZScoreResponse } from '../models/ZScoreResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AnomalyMlService {
    /**
     * Record a behavioral event for an entity
     * Store a time-series observation (login count, API calls, data bytes, etc.)
     * for a user or service entity.
     * @param requestBody
     * @returns RecordEventResponse Successful Response
     * @throws ApiError
     */
    public static recordEventApiV1AnomalyMlEventsPost(
        requestBody: apps__api__anomaly_ml_router__RecordEventRequest,
    ): CancelablePromise<RecordEventResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomaly-ml/events',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Z-score anomaly detection against behavioral baseline
     * Compute z-score for an observed value against the entity's historical baseline.
     *
     * Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
     * The baseline is computed from events in the lookback window.
     * @param requestBody
     * @returns ZScoreResponse Successful Response
     * @throws ApiError
     */
    public static detectZscoreApiV1AnomalyMlDetectZscorePost(
        requestBody: ZScoreRequest,
    ): CancelablePromise<ZScoreResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomaly-ml/detect/zscore',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Isolation Forest multi-dimensional anomaly scoring
     * Score a multi-metric feature vector using a lightweight Isolation Forest.
     *
     * Trains on historical data (window_days) and scores the current observation.
     * Score > 0.6 is flagged as anomalous. No sklearn required.
     * @param requestBody
     * @returns IsolationResponse Successful Response
     * @throws ApiError
     */
    public static scoreIsolationApiV1AnomalyMlDetectIsolationPost(
        requestBody: IsolationRequest,
    ): CancelablePromise<IsolationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomaly-ml/detect/isolation',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Time-series anomaly detection (spike/drop/trend/seasonality)
     * Analyse time-series data for a metric, detecting:
     * - SPIKE: sudden increase > 3x baseline mean
     * - DROP: sudden decrease to < 0.2x baseline mean
     * - TREND_UP/DOWN: sustained directional change > 20% over recent window
     * - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution
     * @param requestBody
     * @returns TimeSeriesResponse Successful Response
     * @throws ApiError
     */
    public static analyzeTimeseriesApiV1AnomalyMlDetectTimeseriesPost(
        requestBody: TimeSeriesRequest,
    ): CancelablePromise<TimeSeriesResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomaly-ml/detect/timeseries',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * UEBA composite risk score for a user
     * Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).
     *
     * Sub-scores:
     * - login_anomaly_score (0-25): login frequency vs baseline
     * - access_pattern_score (0-25): API call patterns vs baseline
     * - data_volume_score (0-25): data egress vs baseline
     * - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)
     * @param userId
     * @param orgId Organisation ID
     * @param windowDays Lookback window
     * @returns UEBARiskResponse Successful Response
     * @throws ApiError
     */
    public static getUserRiskApiV1AnomalyMlUebaUserIdGet(
        userId: string,
        orgId: string = 'default',
        windowDays: number = 7,
    ): CancelablePromise<UEBARiskResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomaly-ml/ueba/{user_id}',
            path: {
                'user_id': userId,
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
     * Get grouped anomaly alerts (alert fatigue reduction)
     * Cluster recent anomalies into alert groups to reduce alert fatigue.
     *
     * Groups by: same entity, same metric across entities, temporal proximity.
     * @param orgId Organisation ID
     * @param windowHours Grouping time window
     * @returns AlertGroupResponse Successful Response
     * @throws ApiError
     */
    public static listAlertGroupsApiV1AnomalyMlGroupsGet(
        orgId: string = 'default',
        windowHours: number = 4,
    ): CancelablePromise<AlertGroupResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomaly-ml/groups',
            query: {
                'org_id': orgId,
                'window_hours': windowHours,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List detected ML anomalies
     * Retrieve persisted ML anomalies with optional filters.
     * @param orgId Organisation ID
     * @param entityId Filter by entity ID
     * @param riskLevel Filter by risk level: low/medium/high/critical
     * @param limit Max results
     * @returns apps__api__anomaly_ml_router__AnomalyListResponse Successful Response
     * @throws ApiError
     */
    public static listAnomaliesApiV1AnomalyMlAnomaliesGet(
        orgId: string = 'default',
        entityId?: (string | null),
        riskLevel?: (string | null),
        limit: number = 100,
    ): CancelablePromise<apps__api__anomaly_ml_router__AnomalyListResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/anomaly-ml/anomalies',
            query: {
                'org_id': orgId,
                'entity_id': entityId,
                'risk_level': riskLevel,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Submit analyst feedback on a detected anomaly
     * Record analyst verdict for an anomaly: true_positive, false_positive,
     * or needs_investigation.
     *
     * Feedback is stored and used to compute per-metric false-positive rates
     * and threshold adjustment recommendations.
     * @param requestBody
     * @returns apps__api__anomaly_ml_router__FeedbackResponse Successful Response
     * @throws ApiError
     */
    public static submitFeedbackApiV1AnomalyMlFeedbackPost(
        requestBody: core__anomaly_ml_engine__FeedbackRequest,
    ): CancelablePromise<apps__api__anomaly_ml_router__FeedbackResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/anomaly-ml/feedback',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
