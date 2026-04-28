/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__analytics_router__DecisionCreate } from '../models/apps__api__analytics_router__DecisionCreate';
import type { apps__api__analytics_router__DecisionResponse } from '../models/apps__api__analytics_router__DecisionResponse';
import type { apps__api__analytics_router__FindingCreate } from '../models/apps__api__analytics_router__FindingCreate';
import type { apps__api__analytics_router__FindingResponse } from '../models/apps__api__analytics_router__FindingResponse';
import type { apps__api__analytics_router__FindingUpdate } from '../models/apps__api__analytics_router__FindingUpdate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AnalyticsService {
    /**
     * Get Dashboard Overview
     * Get security posture overview for dashboard.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardOverviewApiV1AnalyticsDashboardOverviewGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/overview',
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
     * Get Dashboard Summary
     * Compact dashboard summary with key counts and risk score.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardSummaryApiV1AnalyticsDashboardSummaryGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/summary',
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
     * Get Dashboard Severity
     * Severity breakdown for dashboard charts.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardSeverityApiV1AnalyticsDashboardSeverityGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/severity',
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
     * Get Dashboard Scanners
     * Scanner activity breakdown for dashboard.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardScannersApiV1AnalyticsDashboardScannersGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/scanners',
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
     * Get Dashboard Executive
     * Executive dashboard view — alias for /executive with org_id.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardExecutiveApiV1AnalyticsDashboardExecutiveGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/executive',
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
     * Get Analytics Overview
     * High-level analytics overview across all compliance and risk domains.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAnalyticsOverviewApiV1AnalyticsOverviewGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/overview',
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
     * Get Dashboard Trends
     * Get trend data computed from ingested findings over the specified period.
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardTrendsApiV1AnalyticsDashboardTrendsGet(
        days: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/trends',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'days': days,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Top Risks
     * Get top security risks by severity and exploitability.
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTopRisksApiV1AnalyticsDashboardTopRisksGet(
        limit: number = 10,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/top-risks',
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
     * Get Compliance Status
     * Get compliance framework status.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComplianceStatusApiV1AnalyticsDashboardComplianceStatusGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/dashboard/compliance-status',
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
     * Query Findings
     * Query findings with filters. Returns real ingested findings.
     * @param severity
     * @param status
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns apps__api__analytics_router__FindingResponse Successful Response
     * @throws ApiError
     */
    public static queryFindingsApiV1AnalyticsFindingsGet(
        severity?: (string | null),
        status?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<apps__api__analytics_router__FindingResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/findings',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'severity': severity,
                'status': status,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Finding
     * Create a new finding.
     * @param requestBody
     * @returns apps__api__analytics_router__FindingResponse Successful Response
     * @throws ApiError
     */
    public static createFindingApiV1AnalyticsFindingsPost(
        requestBody: apps__api__analytics_router__FindingCreate,
    ): CancelablePromise<apps__api__analytics_router__FindingResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/analytics/findings',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Finding
     * Get finding by ID.
     * @param id
     * @returns apps__api__analytics_router__FindingResponse Successful Response
     * @throws ApiError
     */
    public static getFindingApiV1AnalyticsFindingsIdGet(
        id: string,
    ): CancelablePromise<apps__api__analytics_router__FindingResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/findings/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Finding
     * Update a finding.
     * @param id
     * @param requestBody
     * @returns apps__api__analytics_router__FindingResponse Successful Response
     * @throws ApiError
     */
    public static updateFindingApiV1AnalyticsFindingsIdPut(
        id: string,
        requestBody: apps__api__analytics_router__FindingUpdate,
    ): CancelablePromise<apps__api__analytics_router__FindingResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/analytics/findings/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Query Decisions
     * Query decision history.
     * @param findingId
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns apps__api__analytics_router__DecisionResponse Successful Response
     * @throws ApiError
     */
    public static queryDecisionsApiV1AnalyticsDecisionsGet(
        findingId?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<apps__api__analytics_router__DecisionResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/decisions',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'finding_id': findingId,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Decision
     * Create a new decision record.
     * @param requestBody
     * @returns apps__api__analytics_router__DecisionResponse Successful Response
     * @throws ApiError
     */
    public static createDecisionApiV1AnalyticsDecisionsPost(
        requestBody: apps__api__analytics_router__DecisionCreate,
    ): CancelablePromise<apps__api__analytics_router__DecisionResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/analytics/decisions',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Coverage
     * Get security coverage metrics.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCoverageApiV1AnalyticsCoverageGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/coverage',
        });
    }
    /**
     * Get Roi
     * Get ROI calculations.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRoiApiV1AnalyticsRoiGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/roi',
        });
    }
    /**
     * Get Noise Reduction
     * Get noise reduction metrics.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getNoiseReductionApiV1AnalyticsNoiseReductionGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/noise-reduction',
        });
    }
    /**
     * Run Custom Query
     * Run custom analytics query.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runCustomQueryApiV1AnalyticsCustomQueryPost(
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/analytics/custom-query',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Analytics
     * Export analytics data in specified format.
     * @param format
     * @param dataType
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportAnalyticsApiV1AnalyticsExportGet(
        format: string = 'json',
        dataType: string = 'findings',
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/export',
            query: {
                'format': format,
                'data_type': dataType,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Analytics Stats
     * Get aggregate analytics statistics.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAnalyticsStatsApiV1AnalyticsStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/stats',
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
     * Get Analytics Summary
     * Get analytics summary (alias for /stats).
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAnalyticsSummaryApiV1AnalyticsSummaryGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/summary',
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
     * Severity Over Time
     * Severity distribution over time with moving averages.
     *
     * Returns daily/weekly/monthly counts per severity with a 7-period
     * moving average for trend analysis.
     * @param days
     * @param bucket
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static severityOverTimeApiV1AnalyticsTrendsSeverityOverTimeGet(
        days: number = 30,
        bucket: string = 'day',
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/trends/severity-over-time',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'days': days,
                'bucket': bucket,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Detect Anomalies
     * Anomaly detection on daily finding counts using z-score.
     *
     * Flags days where the z-score exceeds the given threshold (default 2σ).
     * @param days
     * @param threshold
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static detectAnomaliesApiV1AnalyticsTrendsAnomaliesGet(
        days: number = 90,
        threshold: number = 2,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/trends/anomalies',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'days': days,
                'threshold': threshold,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Compare Periods
     * Compare current period metrics against the previous equal-length period.
     *
     * Returns absolute and percentage change for key security KPIs.
     * @param currentDays
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static comparePeriodsApiV1AnalyticsCompareGet(
        currentDays: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/compare',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'current_days': currentDays,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Triage Funnel
     * Get triage funnel metrics showing finding reduction through ALdeci pipeline.
     *
     * Shows the progression: raw scanner findings → deduplicated → correlated →
     * risk-prioritized exposure cases. All numbers are computed from real data.
     * Returns zeros when no data exists rather than fabricated demo numbers.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static triageFunnelApiV1AnalyticsTriageFunnelGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/triage-funnel',
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
     * Risk Velocity
     * Compute risk velocity — rate of risk accumulation/reduction per day.
     *
     * Positive velocity = risk increasing. Negative = risk decreasing.
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static riskVelocityApiV1AnalyticsRiskVelocityGet(
        days: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/risk-velocity',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'days': days,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Executive Summary
     * Executive summary — CISO/CTO-level KPIs, risk posture, compliance.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static executiveSummaryApiV1AnalyticsExecutiveGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/executive',
        });
    }
    /**
     * Analytics Risk Overview
     * Risk overview from analytics data.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyticsRiskOverviewApiV1AnalyticsRiskOverviewGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/risk-overview',
        });
    }
    /**
     * Analytics Sla
     * SLA compliance analytics from findings data.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyticsSlaApiV1AnalyticsSlaGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/sla',
        });
    }
    /**
     * Analytics Live Feed
     * Live feed of recent findings/events.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyticsLiveFeedApiV1AnalyticsLiveFeedGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/live-feed',
        });
    }
    /**
     * False Positive Rate
     * [V3] Get false-positive rate from analyst feedback.
     *
     * Breaks down FP rate by scanner, CWE, and overall. Supports
     * filtering by scanner, CWE, app_id, or org_id.
     *
     * Query params:
     * scanner: Filter by scanner name (e.g. 'semgrep')
     * cwe_id: Filter by CWE (e.g. 'CWE-79')
     * app_id: Filter by application
     * org_id: Filter by organization
     * @param scanner
     * @param cweId
     * @param appId
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static falsePositiveRateApiV1AnalyticsFalsePositiveRateGet(
        scanner?: (string | null),
        cweId?: (string | null),
        appId?: (string | null),
        orgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/false-positive-rate',
            query: {
                'scanner': scanner,
                'cwe_id': cweId,
                'app_id': appId,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
