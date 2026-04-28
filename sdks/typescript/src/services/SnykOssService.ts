/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanFleetRequest } from '../models/ScanFleetRequest';
import type { ScanTenantRequest } from '../models/ScanTenantRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SnykOssService {
    /**
     * Status
     * Report tool availability + fleet readiness.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static statusApiV1ConnectorsSnykOssStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/snyk-oss/status',
        });
    }
    /**
     * Tenants
     * @returns any Successful Response
     * @throws ApiError
     */
    public static tenantsApiV1ConnectorsSnykOssTenantsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/snyk-oss/tenants',
        });
    }
    /**
     * Scan Tenant
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanTenantApiV1ConnectorsSnykOssScanPost(
        requestBody: ScanTenantRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/snyk-oss/scan',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan Fleet
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanFleetApiV1ConnectorsSnykOssScanFleetPost(
        requestBody: ScanFleetRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/snyk-oss/scan-fleet',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
