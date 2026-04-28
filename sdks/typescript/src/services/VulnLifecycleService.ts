/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__vuln_lifecycle_router__TransitionRequest } from '../models/apps__api__vuln_lifecycle_router__TransitionRequest';
import type { apps__api__vuln_lifecycle_router__ValidateRequest } from '../models/apps__api__vuln_lifecycle_router__ValidateRequest';
import type { apps__api__vuln_lifecycle_router__ValidateResponse } from '../models/apps__api__vuln_lifecycle_router__ValidateResponse';
import type { CurrentStageResponse } from '../models/CurrentStageResponse';
import type { TransitionResponse } from '../models/TransitionResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class VulnLifecycleService {
    /**
     * Record a lifecycle stage transition
     * Move a finding to a new lifecycle stage.
     *
     * Enforces the state machine — invalid transitions return HTTP 422.
     * @param findingId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TransitionResponse Successful Response
     * @throws ApiError
     */
    public static transitionFindingApiV1VulnLifecycleFindingIdTransitionPost(
        findingId: string,
        requestBody: apps__api__vuln_lifecycle_router__TransitionRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<TransitionResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/vuln-lifecycle/{finding_id}/transition',
            path: {
                'finding_id': findingId,
            },
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
     * Get full lifecycle history of a finding
     * Return all lifecycle events for a finding in chronological order.
     * @param findingId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TransitionResponse Successful Response
     * @throws ApiError
     */
    public static getLifecycleHistoryApiV1VulnLifecycleFindingIdHistoryGet(
        findingId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<TransitionResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/{finding_id}/history',
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
     * Get the current stage of a finding
     * Return the current lifecycle stage of a finding.
     * @param findingId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns CurrentStageResponse Successful Response
     * @throws ApiError
     */
    public static getCurrentStageApiV1VulnLifecycleFindingIdStageGet(
        findingId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<CurrentStageResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/{finding_id}/stage',
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
     * Count of findings at each stage (org-scoped)
     * Return a count of findings currently at each lifecycle stage for the org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns number Successful Response
     * @throws ApiError
     */
    public static getStageDistributionApiV1VulnLifecycleDistributionGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, number>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/distribution',
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
     * Stages where findings get stuck the longest
     * Return stages sorted by average dwell time (descending).
     *
     * Stages with the highest average hours represent bottlenecks
     * in the remediation pipeline.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getBottlenecksApiV1VulnLifecycleBottlenecksGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/bottlenecks',
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
     * Average hours spent at each lifecycle stage
     * Return the average number of hours findings spend at each stage.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAvgTimePerStageApiV1VulnLifecycleAvgTimeGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/avg-time',
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
     * Flow metrics: throughput, cycle time, lead time, WIP, reopen rate
     * Return aggregate flow metrics for the org:
     *
     * - **throughput**: findings resolved (CLOSED or WONT_FIX)
     * - **cycle_time_hours**: avg hours from IN_PROGRESS to FIXED
     * - **lead_time_hours**: avg hours from DISCOVERED to CLOSED/WONT_FIX
     * - **wip**: findings currently in active (non-terminal) stages
     * - **reopen_rate**: fraction of findings reopened at least once
     * - **total_findings**: total distinct findings tracked
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFlowMetricsApiV1VulnLifecycleFlowGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/vuln-lifecycle/flow',
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
     * Check whether a lifecycle transition is valid
     * Validate a proposed stage transition without recording it.
     *
     * Useful for pre-flight checks in UI before submitting a transition.
     * @param requestBody
     * @returns apps__api__vuln_lifecycle_router__ValidateResponse Successful Response
     * @throws ApiError
     */
    public static validateTransitionApiV1VulnLifecycleValidatePost(
        requestBody: apps__api__vuln_lifecycle_router__ValidateRequest,
    ): CancelablePromise<apps__api__vuln_lifecycle_router__ValidateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/vuln-lifecycle/validate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
