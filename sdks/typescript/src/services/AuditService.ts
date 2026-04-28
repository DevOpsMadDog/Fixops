/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__audit_router__AuditLogResponse } from '../models/apps__api__audit_router__AuditLogResponse';
import type { AuditLogCreate } from '../models/AuditLogCreate';
import type { PaginatedAuditLogResponse } from '../models/PaginatedAuditLogResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AuditService {
    /**
     * List Audit Logs
     * Query audit logs with optional filtering.
     *
     * AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.
     * @param eventType
     * @param userId
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedAuditLogResponse Successful Response
     * @throws ApiError
     */
    public static listAuditLogsApiV1AuditLogsGet(
        eventType?: (string | null),
        userId?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedAuditLogResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/logs',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'event_type': eventType,
                'user_id': userId,
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
     * Export Audit Logs
     * Export audit logs in JSON, CSV, or SIEM-compatible format.
     * @param format
     * @param days
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportAuditLogsApiV1AuditLogsExportGet(
        format: string = 'json',
        days: number = 30,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/logs/export',
            query: {
                'format': format,
                'days': days,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Audit Log
     * Get audit log entry by ID.
     * @param id
     * @returns apps__api__audit_router__AuditLogResponse Successful Response
     * @throws ApiError
     */
    public static getAuditLogApiV1AuditLogsIdGet(
        id: string,
    ): CancelablePromise<apps__api__audit_router__AuditLogResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/logs/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get User Activity
     * Get user activity logs.
     * @param userId
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getUserActivityApiV1AuditUserActivityGet(
        userId: string = 'default',
        limit: number = 100,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/user-activity',
            query: {
                'user_id': userId,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy Changes
     * Get policy change history.
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyChangesApiV1AuditPolicyChangesGet(
        limit: number = 100,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/policy-changes',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Decision Trail
     * Get decision audit trail.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getDecisionTrailApiV1AuditDecisionTrailGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/decision-trail',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Frameworks
     * List supported compliance frameworks.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listFrameworksApiV1AuditComplianceFrameworksGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/compliance/frameworks',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Framework Status
     * Get framework compliance status — real assessment against controls.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFrameworkStatusApiV1AuditComplianceFrameworksIdStatusGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/compliance/frameworks/{id}/status',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Compliance Gaps
     * Get compliance gaps — controls missing audit evidence or with open findings.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComplianceGapsApiV1AuditComplianceFrameworksIdGapsGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/compliance/frameworks/{id}/gaps',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Generate Compliance Report
     * Generate a detailed compliance report for a framework.
     * @param id
     * @param format
     * @returns any Successful Response
     * @throws ApiError
     */
    public static generateComplianceReportApiV1AuditComplianceFrameworksIdReportPost(
        id: string,
        format: string = 'json',
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/audit/compliance/frameworks/{id}/report',
            path: {
                'id': id,
            },
            query: {
                'format': format,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Controls
     * List all compliance controls.
     * @param frameworkId
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listControlsApiV1AuditComplianceControlsGet(
        frameworkId?: (string | null),
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/compliance/controls',
            query: {
                'framework_id': frameworkId,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Append To Chain
     * Append an audit log and link it into the tamper-proof chain.
     *
     * Each log entry's hash includes the previous entry's hash, forming
     * an immutable chain similar to a blockchain.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static appendToChainApiV1AuditLogsChainPost(
        requestBody: AuditLogCreate,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/audit/logs/chain',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Verify Chain
     * Verify the integrity of the entire audit chain.
     *
     * Re-computes hashes from stored logs and checks for tampering.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static verifyChainApiV1AuditChainVerifyGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/chain/verify',
        });
    }
    /**
     * Get Retention Policy
     * Get audit log retention policy settings.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRetentionPolicyApiV1AuditRetentionGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/retention',
        });
    }
    /**
     * Write-audit trail statistics
     * Return aggregated statistics for the write-operation audit trail.
     *
     * Includes: total write count, error rate, method breakdown, top paths.
     * Useful for SOC dashboards and anomaly alerting.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAuditTrailStatsApiV1AuditTrailStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/trail/stats',
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
