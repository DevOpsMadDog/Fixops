/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddApprovalRequest } from '../models/AddApprovalRequest';
import type { apps__api__change_management_router__CompleteRequest } from '../models/apps__api__change_management_router__CompleteRequest';
import type { apps__api__change_management_router__RejectRequest } from '../models/apps__api__change_management_router__RejectRequest';
import type { apps__api__change_management_router__RollbackRequest } from '../models/apps__api__change_management_router__RollbackRequest';
import type { CreateChangeRequest } from '../models/CreateChangeRequest';
import type { CreateFreezePeriodRequest } from '../models/CreateFreezePeriodRequest';
import type { CreateMaintenanceWindowRequest } from '../models/CreateMaintenanceWindowRequest';
import type { ImpactAssessRequest } from '../models/ImpactAssessRequest';
import type { ImplementRequest } from '../models/ImplementRequest';
import type { OverrideRiskRequest } from '../models/OverrideRiskRequest';
import type { SubmitChangeRequest } from '../models/SubmitChangeRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ChangeManagementService {
    /**
     * List Changes
     * List change requests with optional filters.
     * @param status
     * @param riskLevel
     * @param requestorId
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listChangesApiV1ChangesGet(
        status?: (string | null),
        riskLevel?: (string | null),
        requestorId?: (string | null),
        limit: number = 50,
        offset?: number,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes',
            query: {
                'status': status,
                'risk_level': riskLevel,
                'requestor_id': requestorId,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Change
     * Create a new change request in DRAFT status.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createChangeApiV1ChangesPost(
        requestBody: CreateChangeRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Change
     * Get a specific change request by ID.
     * @param changeId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getChangeApiV1ChangesChangeIdGet(
        changeId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/{change_id}',
            path: {
                'change_id': changeId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Submit Change
     * Submit a DRAFT change request for CAB review.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static submitChangeApiV1ChangesChangeIdSubmitPost(
        changeId: string,
        requestBody: SubmitChangeRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/submit',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Approval
     * Add a CAB member approval, rejection, or conditional approval.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addApprovalApiV1ChangesChangeIdApprovePost(
        changeId: string,
        requestBody: AddApprovalRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/approve',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Reject Change
     * Directly reject a change request.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static rejectChangeApiV1ChangesChangeIdRejectPost(
        changeId: string,
        requestBody: apps__api__change_management_router__RejectRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/reject',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Start Implementation
     * Start implementing an APPROVED change.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static startImplementationApiV1ChangesChangeIdImplementPost(
        changeId: string,
        requestBody: ImplementRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/implement',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Complete Change
     * Mark an IMPLEMENTING change as COMPLETED.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static completeChangeApiV1ChangesChangeIdCompletePost(
        changeId: string,
        requestBody: apps__api__change_management_router__CompleteRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/complete',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Rollback Change
     * Execute rollback for a change that is IMPLEMENTING or COMPLETED.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static rollbackChangeApiV1ChangesChangeIdRollbackPost(
        changeId: string,
        requestBody: apps__api__change_management_router__RollbackRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/rollback',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Assess Impact
     * Attach or update impact analysis for a change request.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static assessImpactApiV1ChangesChangeIdImpactPost(
        changeId: string,
        requestBody: ImpactAssessRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/impact',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Override Risk
     * Override risk classification for a change request with justification.
     * @param changeId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static overrideRiskApiV1ChangesChangeIdRiskOverridePost(
        changeId: string,
        requestBody: OverrideRiskRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/{change_id}/risk-override',
            path: {
                'change_id': changeId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Audit Trail
     * Get the full audit trail for a change request.
     * @param changeId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAuditTrailApiV1ChangesChangeIdAuditGet(
        changeId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/{change_id}/audit',
            path: {
                'change_id': changeId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Check Conflicts
     * Check a scheduled change for calendar conflicts and freeze periods.
     * @param changeId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static checkConflictsApiV1ChangesChangeIdConflictsGet(
        changeId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/{change_id}/conflicts',
            path: {
                'change_id': changeId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Maintenance Windows
     * List all maintenance windows.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listMaintenanceWindowsApiV1ChangesCalendarWindowsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/calendar/windows',
        });
    }
    /**
     * Create Maintenance Window
     * Create a new maintenance window.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createMaintenanceWindowApiV1ChangesCalendarWindowsPost(
        requestBody: CreateMaintenanceWindowRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/calendar/windows',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Freeze Periods
     * List all change freeze periods.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listFreezePeriodsApiV1ChangesCalendarFreezesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/calendar/freezes',
        });
    }
    /**
     * Create Freeze Period
     * Create a new change freeze period.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createFreezePeriodApiV1ChangesCalendarFreezesPost(
        requestBody: CreateFreezePeriodRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/calendar/freezes',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Metrics
     * Get change management metrics for the specified period.
     * @param periodDays
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMetricsApiV1ChangesMetricsSummaryGet(
        periodDays: number = 30,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/metrics/summary',
            query: {
                'period_days': periodDays,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Expire Stale Changes
     * Expire change requests that have breached their SLA review deadline.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static expireStaleChangesApiV1ChangesAdminExpireStalePost(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/changes/admin/expire-stale',
        });
    }
}
