/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__sla_router__TrackFindingRequest } from '../models/apps__api__sla_router__TrackFindingRequest';
import type { BulkTrackRequest } from '../models/BulkTrackRequest';
import type { core__sla_manager__SLAPolicy } from '../models/core__sla_manager__SLAPolicy';
import type { EscalateResponse } from '../models/EscalateResponse';
import type { SLAPolicyRequest } from '../models/SLAPolicyRequest';
import type { SLARecord } from '../models/SLARecord';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SlaService {
    /**
     * List Sla
     * List SLA records for the org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listSlaApiV1SlaGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/',
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
     * Create Or Update Policy
     * Create or update the SLA policy for the current org.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns core__sla_manager__SLAPolicy Successful Response
     * @throws ApiError
     */
    public static createOrUpdatePolicyApiV1SlaPoliciesPost(
        requestBody: SLAPolicyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<core__sla_manager__SLAPolicy> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla/policies',
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
     * Get Policy
     * Get the SLA policy for the current org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyApiV1SlaPoliciesGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<(core__sla_manager__SLAPolicy | null)> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/policies',
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
     * Track Finding
     * Start SLA tracking for a finding.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns SLARecord Successful Response
     * @throws ApiError
     */
    public static trackFindingApiV1SlaTrackPost(
        requestBody: apps__api__sla_router__TrackFindingRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<SLARecord> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla/track',
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
     * Bulk Track
     * Track multiple findings at once.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static bulkTrackApiV1SlaTrackBulkPost(
        requestBody: BulkTrackRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla/track/bulk',
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
     * Get Sla Status
     * Get the current SLA status for a specific finding.
     * @param findingId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSlaStatusApiV1SlaStatusFindingIdGet(
        findingId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/status/{finding_id}',
            path: {
                'finding_id': findingId,
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
     * Get Breached
     * Return all breached SLA findings for the current org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns SLARecord Successful Response
     * @throws ApiError
     */
    public static getBreachedApiV1SlaBreachedGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<SLARecord>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/breached',
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
     * Get At Risk
     * Return findings approaching their SLA deadline.
     * @param hoursThreshold
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns SLARecord Successful Response
     * @throws ApiError
     */
    public static getAtRiskApiV1SlaAtRiskGet(
        hoursThreshold: number = 24,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<SLARecord>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/at-risk',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'hours_threshold': hoursThreshold,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Compliance
     * Return the SLA compliance rate for the current org.
     * @param periodDays
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComplianceApiV1SlaComplianceGet(
        periodDays: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/compliance',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'period_days': periodDays,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Dashboard
     * Return all SLA metrics for dashboard display.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDashboardApiV1SlaDashboardGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/dashboard',
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
     * Run Escalation
     * Run escalation check — alerts on all breached, un-escalated findings.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns EscalateResponse Successful Response
     * @throws ApiError
     */
    public static runEscalationApiV1SlaEscalatePost(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<EscalateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/sla/escalate',
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
     * Sla Dashboard Legacy
     * Legacy SLA compliance dashboard — breach counts from remediation tasks.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static slaDashboardLegacyApiV1SlaDashboardLegacyGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/dashboard-legacy',
        });
    }
    /**
     * Sla Metrics
     * Detailed SLA metrics — MTTR, team breakdown, escalations.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static slaMetricsApiV1SlaMetricsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/metrics',
        });
    }
    /**
     * Sla Breaches
     * List current SLA breaches (task-level, legacy view).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static slaBreachesApiV1SlaBreachesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/breaches',
        });
    }
    /**
     * Sla Health
     * SLA service health check.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static slaHealthApiV1SlaHealthGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/sla/health',
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
}
