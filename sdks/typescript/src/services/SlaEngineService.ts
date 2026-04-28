/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AlertsResponse } from '../models/AlertsResponse';
import type { apps__api__sla_engine_router__CreatePolicyRequest } from '../models/apps__api__sla_engine_router__CreatePolicyRequest';
import type { apps__api__sla_engine_router__TrackFindingRequest } from '../models/apps__api__sla_engine_router__TrackFindingRequest';
import type { core__sla_engine__SLAPolicy } from '../models/core__sla_engine__SLAPolicy';
import type { core__sla_engine__SLAStatus } from '../models/core__sla_engine__SLAStatus';
import type { SLATracking } from '../models/SLATracking';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SlaEngineService {
    /**
     * Start tracking a finding against SLA
     * Begin SLA tracking for a security finding. Idempotent — returns existing record if already tracked.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns SLATracking Successful Response
     * @throws ApiError
     */
    public static trackFindingApiV1SlaEngineTrackPost(
        requestBody: apps__api__sla_engine_router__TrackFindingRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<SLATracking> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla-engine/track',
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
     * Get SLA status for a finding
     * Return ON_TRACK, AT_RISK, BREACHED, or RESOLVED for a tracked finding.
     * @param findingId
     * @returns core__sla_engine__SLAStatus Successful Response
     * @throws ApiError
     */
    public static getStatusApiV1SlaEngineStatusFindingIdGet(
        findingId: string,
    ): CancelablePromise<core__sla_engine__SLAStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla-engine/status/{finding_id}',
            path: {
                'finding_id': findingId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List findings at risk of SLA breach
     * Return all findings currently AT_RISK or BREACHED for the org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns core__sla_engine__SLAStatus Successful Response
     * @throws ApiError
     */
    public static getAtRiskApiV1SlaEngineAtRiskGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<core__sla_engine__SLAStatus>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla-engine/at-risk',
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
     * SLA dashboard stats
     * Aggregate SLA metrics: counts by status, compliance rate.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardApiV1SlaEngineDashboardGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla-engine/dashboard',
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
     * SLA compliance rate for past N days
     * Calculate SLA compliance rate: % of resolved findings fixed within deadline.
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComplianceRateApiV1SlaEngineComplianceRateGet(
        days: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla-engine/compliance-rate',
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
     * Mark a finding as resolved
     * Record that a finding has been resolved. SLA is marked met or breached based on timing.
     * @param findingId
     * @returns core__sla_engine__SLAStatus Successful Response
     * @throws ApiError
     */
    public static resolveFindingApiV1SlaEngineResolveFindingIdPost(
        findingId: string,
    ): CancelablePromise<core__sla_engine__SLAStatus> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla-engine/resolve/{finding_id}',
            path: {
                'finding_id': findingId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create or update a named SLA policy
     * Create a named SLA policy with per-severity deadlines (in hours).
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns core__sla_engine__SLAPolicy Successful Response
     * @throws ApiError
     */
    public static createPolicyApiV1SlaEnginePolicyPost(
        requestBody: apps__api__sla_engine_router__CreatePolicyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<core__sla_engine__SLAPolicy> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla-engine/policy',
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
     * Trigger breach alert scan
     * Scan all tracked findings and send alerts for those >90% through their deadline.
     * @returns AlertsResponse Successful Response
     * @throws ApiError
     */
    public static sendBreachAlertsApiV1SlaEngineAlertsPost(): CancelablePromise<AlertsResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla-engine/alerts',
        });
    }
}
