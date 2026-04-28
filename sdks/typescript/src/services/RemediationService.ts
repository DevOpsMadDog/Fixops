/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__remediation_router__CreatePlanRequest } from '../models/apps__api__remediation_router__CreatePlanRequest';
import type { apps__api__remediation_router__CreateTaskRequest } from '../models/apps__api__remediation_router__CreateTaskRequest';
import type { apps__api__remediation_router__LinkTicketRequest } from '../models/apps__api__remediation_router__LinkTicketRequest';
import type { apps__api__remediation_router__UpdateStatusRequest } from '../models/apps__api__remediation_router__UpdateStatusRequest';
import type { apps__api__remediation_router__VerifyFixRequest } from '../models/apps__api__remediation_router__VerifyFixRequest';
import type { AssignTaskRequest } from '../models/AssignTaskRequest';
import type { AutoFixTaskRequest } from '../models/AutoFixTaskRequest';
import type { SubmitVerificationRequest } from '../models/SubmitVerificationRequest';
import type { SuggestFixRequest } from '../models/SuggestFixRequest';
import type { UpdatePlanStateRequest } from '../models/UpdatePlanStateRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class RemediationService {
    /**
     * Create Task
     * Create a new remediation task.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createTaskApiV1RemediationTasksPost(
        requestBody: apps__api__remediation_router__CreateTaskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/tasks',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Tasks
     * List remediation tasks with optional filters.
     * @param appId
     * @param status
     * @param assignee
     * @param severity
     * @param overdueOnly
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listTasksApiV1RemediationTasksGet(
        appId?: (string | null),
        status?: (string | null),
        assignee?: (string | null),
        severity?: (string | null),
        overdueOnly: boolean = false,
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/tasks',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'app_id': appId,
                'status': status,
                'assignee': assignee,
                'severity': severity,
                'overdue_only': overdueOnly,
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
     * Get Task
     * Get a specific task by ID.
     * @param taskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTaskApiV1RemediationTasksTaskIdGet(
        taskId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/tasks/{task_id}',
            path: {
                'task_id': taskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Task Status
     * Update task status with state machine validation.
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateTaskStatusApiV1RemediationTasksTaskIdStatusPut(
        taskId: string,
        requestBody: apps__api__remediation_router__UpdateStatusRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/remediation/tasks/{task_id}/status',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Assign Task
     * Assign task to a user.
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static assignTaskApiV1RemediationTasksTaskIdAssignPut(
        taskId: string,
        requestBody: AssignTaskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/remediation/tasks/{task_id}/assign',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Submit Verification
     * Submit verification evidence for a task.
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static submitVerificationApiV1RemediationTasksTaskIdVerificationPost(
        taskId: string,
        requestBody: SubmitVerificationRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/tasks/{task_id}/verification',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Link Ticket
     * Link task to external ticket.
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static linkTicketApiV1RemediationTasksTaskIdTicketPut(
        taskId: string,
        requestBody: apps__api__remediation_router__LinkTicketRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/remediation/tasks/{task_id}/ticket',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Check Sla Breaches
     * Check for SLA breaches and record them.
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static checkSlaBreachesApiV1RemediationSlaCheckPost(
        orgId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/sla/check',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Metrics
     * Get remediation metrics including MTTR.
     * @param orgId
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMetricsApiV1RemediationMetricsOrgIdGet(
        orgId: string,
        appId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/metrics/{org_id}',
            path: {
                'org_id': orgId,
            },
            query: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Valid Statuses
     * List all valid remediation statuses.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listValidStatusesApiV1RemediationStatusesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/statuses',
        });
    }
    /**
     * Autofix Task
     * Generate an AI-powered autofix for a remediation task.
     *
     * Uses the task metadata to generate a code fix, dependency update,
     * or configuration change. Optionally creates a pull request.
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static autofixTaskApiV1RemediationTasksTaskIdAutofixPost(
        taskId: string,
        requestBody: AutoFixTaskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/tasks/{task_id}/autofix',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Task Autofix Suggestions
     * Get existing autofix suggestions for a remediation task.
     * @param taskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet(
        taskId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/tasks/{task_id}/autofix/suggestions',
            path: {
                'task_id': taskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Transition Task Status
     * Transition task status (CLI-compatible alias for /tasks/{task_id}/status).
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static transitionTaskStatusApiV1RemediationTasksTaskIdTransitionPut(
        taskId: string,
        requestBody: apps__api__remediation_router__UpdateStatusRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/remediation/tasks/{task_id}/transition',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Verify Task
     * Verify task (CLI-compatible alias for /tasks/{task_id}/verification).
     * @param taskId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyTaskApiV1RemediationTasksTaskIdVerifyPost(
        taskId: string,
        requestBody: SubmitVerificationRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/tasks/{task_id}/verify',
            path: {
                'task_id': taskId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Global Metrics
     * Get global remediation metrics (CLI-compatible endpoint).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getGlobalMetricsApiV1RemediationMetricsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/metrics',
        });
    }
    /**
     * Get Remediation Backlog
     * Return the sprint-aware security remediation backlog.
     *
     * Query parameters:
     * - **severity**: Filter by severity level (critical, high, medium, low)
     * - **sprint**: Pass ``current`` to return only sprint-eligible (open/active, non-overdue) tasks
     * - **assignee**: Filter by assignee username; use ``unassigned`` to return tasks with no assignee
     * - **limit**: Maximum number of items to return (default 50, max 500)
     * @param severity Filter by severity: critical|high|medium|low
     * @param sprint 'current' returns only sprint-eligible tasks
     * @param assignee Filter by assignee; 'unassigned' returns tasks with no assignee
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRemediationBacklogApiV1RemediationBacklogGet(
        severity?: (string | null),
        sprint?: (string | null),
        assignee?: (string | null),
        limit: number = 50,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/backlog',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'severity': severity,
                'sprint': sprint,
                'assignee': assignee,
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remediation Stats
     * Remediation statistics — task counts by severity/status/assignee.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static remediationStatsApiV1RemediationStatsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/stats',
        });
    }
    /**
     * Remediation Queue
     * Remediation queue — pending tasks ordered by priority.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static remediationQueueApiV1RemediationQueueGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/queue',
        });
    }
    /**
     * Remediation Summary
     * Remediation summary — high-level overview.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static remediationSummaryApiV1RemediationSummaryGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/summary',
        });
    }
    /**
     * Get Task Timeline
     * Full remediation lifecycle timeline for a task.
     *
     * Returns every phase of the finding lifecycle:
     * discovery → triage → ticket → fix → verification → evidence,
     * assembled from task_history, task metadata, and linked evidence.
     * @param taskId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTaskTimelineApiV1RemediationTasksTaskIdTimelineGet(
        taskId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/tasks/{task_id}/timeline',
            path: {
                'task_id': taskId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create CWE-based remediation plan
     * Generate a step-by-step remediation plan for a finding based on its CWE ID.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPlanApiV1RemediationPlanPost(
        requestBody: apps__api__remediation_router__CreatePlanRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/plan',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all remediation plans
     * List remediation plans with optional filters.
     * @param findingId
     * @param state
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPlansApiV1RemediationPlansGet(
        findingId?: (string | null),
        state?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/plans',
            query: {
                'finding_id': findingId,
                'state': state,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update plan state
     * Advance a remediation plan through its state machine.
     * @param planId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updatePlanStateApiV1RemediationPlanIdStatusPut(
        planId: string,
        requestBody: UpdatePlanStateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/remediation/{plan_id}/status',
            path: {
                'plan_id': planId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get code fix suggestion for a finding
     * Return a safe code fix suggestion based on the finding's CWE ID.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static suggestFixApiV1RemediationSuggestFixPost(
        requestBody: SuggestFixRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/suggest-fix',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Verify fix via re-scan results
     * Check whether a finding still appears in new scan results.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyFixApiV1RemediationVerifyPost(
        requestBody: apps__api__remediation_router__VerifyFixRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/remediation/verify',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List CWE remediation templates
     * Return all built-in CWE remediation templates with effort and step counts.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listCweTemplatesApiV1RemediationCweTemplatesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/cwe-templates',
        });
    }
    /**
     * Get SLA deadline for a severity
     * Return the SLA timedelta and hours for a given severity level.
     * @param severity
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSlaApiV1RemediationSlaGet(
        severity: string = 'MEDIUM',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/remediation/sla',
            query: {
                'severity': severity,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
