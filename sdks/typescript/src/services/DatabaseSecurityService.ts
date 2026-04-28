/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddDatabaseRequest } from '../models/AddDatabaseRequest';
import type { apps__api__db_security_router__ScanRequest } from '../models/apps__api__db_security_router__ScanRequest';
import type { DataExposureRequest } from '../models/DataExposureRequest';
import type { PrivilegeAuditRequest } from '../models/PrivilegeAuditRequest';
import type { QueryAuditRequest } from '../models/QueryAuditRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DatabaseSecurityService {
    /**
     * List Databases
     * List all registered databases with inventory summary.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listDatabasesApiV1DbSecurityInventoryGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/db-security/inventory',
        });
    }
    /**
     * Add Database
     * Register a database in the inventory.
     *
     * Tracks type, version, host, port, TLS status, backup configuration,
     * and public-facing exposure for downstream scanning.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addDatabaseApiV1DbSecurityInventoryPost(
        requestBody: AddDatabaseRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/db-security/inventory',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove Database
     * Remove a database from the inventory.
     * @param dbId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static removeDatabaseApiV1DbSecurityInventoryDbIdDelete(
        dbId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/db-security/inventory/{db_id}',
            path: {
                'db_id': dbId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan Database
     * Run a full CIS benchmark + privilege + exposure + backup + connection + query scan.
     *
     * Returns a comprehensive scan result with risk score (0-100) and all findings.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanDatabaseApiV1DbSecurityScanPost(
        requestBody: apps__api__db_security_router__ScanRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/db-security/scan',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Scan Result
     * Retrieve the latest scan result for a database.
     * @param dbId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getScanResultApiV1DbSecurityScanDbIdGet(
        dbId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/db-security/scan/{db_id}',
            path: {
                'db_id': dbId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Privilege Audit
     * Audit database user privileges for over-provisioning, default passwords, shared accounts.
     *
     * Returns per-user risk scores and privilege details.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static privilegeAuditApiV1DbSecurityPrivilegeAuditPost(
        requestBody: PrivilegeAuditRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/db-security/privilege-audit',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Exposure Detection
     * Detect PII and sensitive data in unencrypted or unmasked columns.
     *
     * Analyzes column names against PII patterns (SSN, credit card, email, passwords, etc.).
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exposureDetectionApiV1DbSecurityExposureDetectionPost(
        requestBody: DataExposureRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/db-security/exposure-detection',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Query Audit
     * Analyze query audit logs for suspicious patterns.
     *
     * Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
     * privilege escalation, and more (14 pattern categories).
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static queryAuditApiV1DbSecurityQueryAuditPost(
        requestBody: QueryAuditRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/db-security/query-audit',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Posture Summary
     * Return aggregate security posture across all scanned databases.
     *
     * Includes average risk score, finding counts by severity, and per-database ranking.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static postureSummaryApiV1DbSecurityPostureGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/db-security/posture',
        });
    }
}
