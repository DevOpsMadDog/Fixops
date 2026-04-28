/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__container_security_connector_router__ScanRequest } from '../models/apps__api__container_security_connector_router__ScanRequest';
import type { apps__api__container_security_connector_router__ScanResponse } from '../models/apps__api__container_security_connector_router__ScanResponse';
import type { ToolStatusResponse } from '../models/ToolStatusResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ContainerSecurityConnectorService {
    /**
     * Health
     * @returns any Successful Response
     * @throws ApiError
     */
    public static healthApiV1ConnectorsContainerSecurityHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/container-security/health',
        });
    }
    /**
     * Status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static statusApiV1ConnectorsContainerSecurityStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/container-security/status',
        });
    }
    /**
     * Tools
     * @returns ToolStatusResponse Successful Response
     * @throws ApiError
     */
    public static toolsApiV1ConnectorsContainerSecurityToolsGet(): CancelablePromise<ToolStatusResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/container-security/tools',
        });
    }
    /**
     * Tenants
     * @param tenantsRoot
     * @returns any Successful Response
     * @throws ApiError
     */
    public static tenantsApiV1ConnectorsContainerSecurityTenantsGet(
        tenantsRoot?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/container-security/tenants',
            query: {
                'tenants_root': tenantsRoot,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns apps__api__container_security_connector_router__ScanResponse Successful Response
     * @throws ApiError
     */
    public static scanApiV1ConnectorsContainerSecurityScanPost(
        requestBody: apps__api__container_security_connector_router__ScanRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<apps__api__container_security_connector_router__ScanResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/container-security/scan',
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
     * History
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static historyApiV1ConnectorsContainerSecurityHistoryGet(
        limit: number = 50,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/container-security/history',
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
}
