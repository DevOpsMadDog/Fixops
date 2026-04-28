/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__fail_router__CreateScenarioRequest } from '../models/apps__api__fail_router__CreateScenarioRequest';
import type { apps__api__fail_router__DetectRequest } from '../models/apps__api__fail_router__DetectRequest';
import type { apps__api__fail_router__RemediateRequest } from '../models/apps__api__fail_router__RemediateRequest';
import type { GradeRequest } from '../models/GradeRequest';
import type { GradeResponse } from '../models/GradeResponse';
import type { InjectRequest } from '../models/InjectRequest';
import type { InjectResponse } from '../models/InjectResponse';
import type { LogActivityRequest } from '../models/LogActivityRequest';
import type { TriageRequest } from '../models/TriageRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class FailEngineService {
    /**
     * Inject a synthetic vulnerability (create drill)
     * Inject a synthetic vulnerability finding into the FixOps pipeline.
     *
     * This creates a FAIL Engine drill — the synthetic finding will appear
     * in the normal finding feed for the target component, indistinguishable
     * from a real finding. The clock starts ticking from injection time.
     *
     * Available scenarios: log4shell, sqli, ssrf, path_traversal,
     * insecure_deserialization, hardcoded_credentials, broken_auth, xss,
     * crypto_weakness, supply_chain.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns InjectResponse Created drill with injection metadata
     * @throws ApiError
     */
    public static injectVulnerabilityApiV1FailInjectPost(
        requestBody: InjectRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<InjectResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/inject',
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
     * List active / historical drills
     * List drills for an organisation.
     *
     * By default returns only active drills (pending, active, detected, triaged,
     * remediated). Set history=true to include graded and cancelled drills.
     * @param history Include historical (graded/cancelled) drills
     * @param days Days of history to include
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listDrillsApiV1FailDrillsGet(
        history: boolean = false,
        days: number = 90,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/drills',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'history': history,
                'days': days,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Drill detail with timeline and score
     * Get full detail for a drill including timeline events and score breakdown.
     * @param drillId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDrillApiV1FailDrillsDrillIdGet(
        drillId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/drills/{drill_id}',
            path: {
                'drill_id': drillId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Cancel an active drill
     * Cancel an active drill without grading it.
     *
     * The drill will be marked as cancelled and removed from the active list.
     * Cancelled drills are excluded from readiness scoring.
     * @param drillId
     * @param cancelledBy Who is cancelling the drill
     * @param reason Reason for cancellation
     * @returns any Successful Response
     * @throws ApiError
     */
    public static cancelDrillApiV1FailDrillsDrillIdDelete(
        drillId: string,
        cancelledBy?: (string | null),
        reason: string = '',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/fail/drills/{drill_id}',
            path: {
                'drill_id': drillId,
            },
            query: {
                'cancelled_by': cancelledBy,
                'reason': reason,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mark drill finding as detected
     * Signal that the synthetic finding was detected by the security team.
     * This records the detection timestamp and starts the triage clock.
     * @param drillId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static markDetectedApiV1FailDrillsDrillIdDetectPost(
        drillId: string,
        requestBody: apps__api__fail_router__DetectRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/drills/{drill_id}/detect',
            path: {
                'drill_id': drillId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mark drill finding as triaged
     * Record the triage outcome: classification, escalation, and teams notified.
     * This is used by the scorer to assess triage accuracy and communication quality.
     * @param drillId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static markTriagedApiV1FailDrillsDrillIdTriagePost(
        drillId: string,
        requestBody: TriageRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/drills/{drill_id}/triage',
            path: {
                'drill_id': drillId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mark drill finding as remediated
     * Signal that the synthetic finding was remediated.
     * This records the remediation timestamp for speed scoring.
     * @param drillId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static markRemediatedApiV1FailDrillsDrillIdRemediatePost(
        drillId: string,
        requestBody: apps__api__fail_router__RemediateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/drills/{drill_id}/remediate',
            path: {
                'drill_id': drillId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Grade team response to a drill
     * Compute and persist the 4-dimension drill score.
     *
     * Scoring dimensions:
     * - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
     * - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
     * - **Remediation Speed** (30%) — How fast was the fix applied?
     * - **Communication** (15%) — Was the right team notified? Escalation followed?
     *
     * Overall = weighted average of all four dimensions (0-10 scale).
     * @param drillId
     * @param requestBody
     * @returns GradeResponse Successful Response
     * @throws ApiError
     */
    public static gradeDrillApiV1FailDrillsDrillIdGradePost(
        drillId: string,
        requestBody: GradeRequest,
    ): CancelablePromise<GradeResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/drills/{drill_id}/grade',
            path: {
                'drill_id': drillId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Components with no recent security activity
     * Return all components that have had no security activity (scan, review, drill)
     * within the threshold period.
     *
     * Risk amplification rules:
     * - Component inactive 90+ days → flagged
     * - Component inactive + holds critical data → **urgent**
     * - Each neglect zone includes a suggested drill scenario
     *
     * Use this to proactively target under-tested components for FAIL drills.
     * @param thresholdDays Days of inactivity to flag as neglected
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getNeglectZonesApiV1FailNeglectZonesGet(
        thresholdDays: number = 90,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/neglect-zones',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'threshold_days': thresholdDays,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Organisation readiness score
     * Compute the organisation's security readiness score based on drill history.
     *
     * Readiness = rolling average of the last 10 graded drill scores.
     *
     * Returns:
     * - Overall score (0-10)
     * - Per-dimension averages (detection, triage, remediation, communication)
     * - Per-team breakdown
     * - Trend (improving / declining / stable)
     * - Industry benchmark comparison
     * - Percentile ranking
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getReadinessScoreApiV1FailReadinessScoreGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/readiness-score',
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
     * Industry benchmark comparison
     * Compare organisation readiness score against the industry benchmark.
     *
     * The default benchmark is 6.5/10 (configurable at engine init).
     * Returns a delta, percentile estimate, and an assessment string.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComparisonApiV1FailComparisonGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/comparison',
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
     * List available injection scenarios
     * List all available FAIL injection scenarios (built-in and custom).
     *
     * Each scenario includes:
     * - Synthetic finding payload (CVE, CVSS, evidence)
     * - MITRE ATT&CK technique/tactic mapping
     * - CWE identifiers
     * - Expected detection timeline and triage classification
     * - Recommended remediation approach
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listScenariosApiV1FailScenariosGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/scenarios',
        });
    }
    /**
     * Create a custom injection scenario
     * Create a custom FAIL injection scenario.
     *
     * Custom scenarios allow organisations to test detection of domain-specific
     * vulnerabilities that are not covered by the 10 built-in scenarios.
     *
     * The synthetic_finding payload should mimic what a real scanner would report
     * for this vulnerability class — the closer to reality, the more valid the test.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createScenarioApiV1FailScenariosPost(
        requestBody: apps__api__fail_router__CreateScenarioRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/scenarios',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export labeled training samples
     * Export labeled training samples generated from completed drills.
     *
     * Each sample includes two labeled signals for ML feedback loops:
     * - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
     * - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}
     *
     * These samples feed into the self-learning detection and triage loops:
     * - Loop 1: Detection model — learns what "fast detection" looks like per scenario
     * - Loop 2: Triage model — learns correct severity classification per finding type
     * @param scenarioId Filter by scenario
     * @param limit Maximum samples to return
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTrainingDataApiV1FailTrainingDataGet(
        scenarioId?: (string | null),
        limit: number = 1000,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/training-data',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'scenario_id': scenarioId,
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Log a security activity for neglect zone tracking
     * Log a security activity event for a component.
     *
     * This is used to track when components have been scanned, reviewed, or
     * drilled, so the neglect zone detector can accurately identify blind spots.
     *
     * Activity types: scan, review, drill, pentest, audit
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static logActivityApiV1FailActivityPost(
        requestBody: LogActivityRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/fail/activity',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * FAIL Engine health check
     * Health check for the FAIL Engine (suite-attack edition).
     *
     * Returns engine version, scenario count, and database path.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthCheckApiV1FailHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/health',
        });
    }
    /**
     * List FAIL scores
     * List FAIL scores (paginated, sorted by score DESC).
     * @param grade Filter by grade
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listScoresApiV1FailScoresGet(
        grade?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/scores',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'grade': grade,
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
     * Top risks by FAIL score
     * Get the highest-risk findings by FAIL score.
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static topRisksApiV1FailTopRisksGet(
        limit: number = 20,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/top-risks',
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
     * FAIL score statistics
     * Aggregate FAIL scoring statistics.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static failStatsApiV1FailStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/fail/stats',
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
