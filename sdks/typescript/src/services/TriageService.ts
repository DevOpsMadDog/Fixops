/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriageEnrichRequest } from '../models/TriageEnrichRequest';
import type { TriageEnrichResponse } from '../models/TriageEnrichResponse';
import type { TriageFeedbackRequest } from '../models/TriageFeedbackRequest';
import type { TriageFeedbackResponse } from '../models/TriageFeedbackResponse';
import type { TriageQueueResponse } from '../models/TriageQueueResponse';
import type { TriageStatsResponse } from '../models/TriageStatsResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TriageService {
    /**
     * Triage Health
     * Health check for triage subsystem.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static triageHealthApiV1TriageHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/triage/health',
        });
    }
    /**
     * Triage Status
     * Status of the triage enrichment subsystem.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static triageStatusApiV1TriageStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/triage/status',
        });
    }
    /**
     * Enrich Findings
     * Enrich one or more findings with attack paths, compliance impact,
     * SLA deadlines, and self-learning confidence adjustments.
     *
     * This is the unified triage endpoint: one call, everything you need to
     * make a triage decision.  Subsystems that are unavailable are gracefully
     * skipped and indicated in ``enrichment_available``.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TriageEnrichResponse Successful Response
     * @throws ApiError
     */
    public static enrichFindingsApiV1TriageEnrichPost(
        requestBody: TriageEnrichRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<TriageEnrichResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/triage/enrich',
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
     * Submit Feedback
     * Record analyst feedback on a triaged finding.
     *
     * Stores verdict in ``triage_feedback`` table and, if the self-learning
     * engine is available, records a decision-outcome feedback event so the
     * platform learns from analyst corrections over time.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TriageFeedbackResponse Successful Response
     * @throws ApiError
     */
    public static submitFeedbackApiV1TriageFeedbackPost(
        requestBody: TriageFeedbackRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<TriageFeedbackResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/triage/feedback',
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
     * Triage Stats
     * Triage performance statistics.
     *
     * Returns analyst agreement rate, false-positive trending, and verdict
     * breakdown computed from the ``triage_feedback`` table.
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TriageStatsResponse Successful Response
     * @throws ApiError
     */
    public static triageStatsApiV1TriageStatsGet(
        days: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<TriageStatsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/triage/stats',
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
     * Triage Queue
     * Smart triage queue.
     *
     * Returns untriaged findings ordered by a composite priority score:
     * ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``
     *
     * Findings that already have analyst feedback are excluded.  Results
     * are bucketed into four groups: ``requires_immediate_action``,
     * ``high_priority``, ``standard``, and ``can_wait``.
     *
     * By default, pre-seeded demo findings are excluded. Pass
     * ``include_demo=true`` to show them.
     * @param limit
     * @param offset
     * @param includeDemo Include demo/seeded findings
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns TriageQueueResponse Successful Response
     * @throws ApiError
     */
    public static triageQueueApiV1TriageQueueGet(
        limit: number = 100,
        offset?: number,
        includeDemo: boolean = false,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<TriageQueueResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/triage/queue',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'offset': offset,
                'include_demo': includeDemo,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
