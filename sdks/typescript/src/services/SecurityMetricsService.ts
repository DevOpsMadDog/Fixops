/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__security_metrics_router__KeyResultUpdate } from '../models/apps__api__security_metrics_router__KeyResultUpdate';
import type { apps__api__security_metrics_router__ObjectiveCreate } from '../models/apps__api__security_metrics_router__ObjectiveCreate';
import type { apps__api__security_metrics_router__ReportRequest } from '../models/apps__api__security_metrics_router__ReportRequest';
import type { DeploymentRecord } from '../models/DeploymentRecord';
import type { EventIngest } from '../models/EventIngest';
import type { KeyResultAdd } from '../models/KeyResultAdd';
import type { ROIRequest } from '../models/ROIRequest';
import { TrendPeriod } from '../models/TrendPeriod';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SecurityMetricsService {
    /**
     * DORA-like security metrics
     * Compute Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), Mean Time to Remediate (MTTR), and Change Failure Rate for the requested time window.
     * @param days Lookback window in days
     * @param since Window start (ISO 8601)
     * @param until Window end (ISO 8601)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDoraMetricsApiV1MetricsDoraGet(
        days: number = 30,
        since?: (string | null),
        until?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/dora',
            query: {
                'days': days,
                'since': since,
                'until': until,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Industry benchmark comparison
     * Compare org DORA metrics against Verizon DBIR 2024 and SANS 2024 benchmarks. Returns percentile ranking for each metric.
     * @param days
     * @param industry Industry vertical
     * @param since
     * @param until
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getBenchmarksApiV1MetricsBenchmarksGet(
        days: number = 30,
        industry: string = 'global_median',
        since?: (string | null),
        until?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/benchmarks',
            query: {
                'days': days,
                'industry': industry,
                'since': since,
                'until': until,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Time-series trend data
     * Generate time-series data for vulnerability backlog, risk score, compliance percentage, and incident count. Supports weekly, monthly, and quarterly rollups.
     * @param period Rollup period
     * @param periods Number of periods to return
     * @param until End of last bucket (ISO 8601)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTrendsApiV1MetricsTrendsGet(
        period: TrendPeriod = TrendPeriod.WEEKLY,
        periods: number = 12,
        until?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/trends',
            query: {
                'period': period,
                'periods': periods,
                'until': until,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * SLA compliance per severity
     * Track SLA compliance for Critical (24h), High (7d), Medium (30d), and Low (90d) findings. Returns breach rate, average overdue time, and worst-offender team/repo.
     * @param days
     * @param since
     * @param until
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSlaComplianceApiV1MetricsSlaGet(
        days: number = 30,
        since?: (string | null),
        until?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/sla',
            query: {
                'days': days,
                'since': since,
                'until': until,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Security program ROI calculation
     * Calculate security program ROI: cost vs avoided losses using Ponemon/IBM 2024 breach cost data. Returns net benefit and payback period.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static calculateRoiApiV1MetricsRoiPost(
        requestBody: ROIRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/roi',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all OKR objectives
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listObjectivesApiV1MetricsObjectivesGet(): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/metrics/objectives',
        });
    }
    /**
     * Create an OKR objective
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createObjectiveApiV1MetricsObjectivesPost(
        requestBody: apps__api__security_metrics_router__ObjectiveCreate,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/objectives',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add a key result to an objective
     * @param objId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addKeyResultApiV1MetricsObjectivesObjIdKeyResultsPost(
        objId: string,
        requestBody: KeyResultAdd,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/objectives/{obj_id}/key-results',
            path: {
                'obj_id': objId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update key result progress
     * @param objId
     * @param krId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch(
        objId: string,
        krId: string,
        requestBody: apps__api__security_metrics_router__KeyResultUpdate,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/v1/metrics/objectives/{obj_id}/key-results/{kr_id}',
            path: {
                'obj_id': objId,
                'kr_id': krId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete an OKR objective
     * @param objId
     * @returns void
     * @throws ApiError
     */
    public static deleteObjectiveApiV1MetricsObjectivesObjIdDelete(
        objId: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/metrics/objectives/{obj_id}',
            path: {
                'obj_id': objId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Ingest a security event
     * Record a security event to feed MTTD/MTTC/MTTR calculations.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestEventApiV1MetricsEventsPost(
        requestBody: EventIngest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/events',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Record a deployment
     * Record a deployment event for Change Failure Rate tracking.
     * @param requestBody
     * @returns string Successful Response
     * @throws ApiError
     */
    public static recordDeploymentApiV1MetricsDeploymentsPost(
        requestBody: DeploymentRecord,
    ): CancelablePromise<Record<string, string>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/deployments',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Generate a periodic security report
     * Generate weekly digest, monthly executive summary, quarterly board report, or annual security review. Returns report metadata and sections.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static generateReportApiV1MetricsReportsPost(
        requestBody: apps__api__security_metrics_router__ReportRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/metrics/reports',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
