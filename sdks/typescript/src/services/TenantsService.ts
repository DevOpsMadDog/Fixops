/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CurrentTenantResponse } from '../models/CurrentTenantResponse';
import type { DeleteTenantResponse } from '../models/DeleteTenantResponse';
import type { TenantListResponse } from '../models/TenantListResponse';
import type { TenantStatsResponse } from '../models/TenantStatsResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TenantsService {
    /**
     * Current tenant info
     * Return the org_id for the currently authenticated request.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns CurrentTenantResponse Successful Response
     * @throws ApiError
     */
    public static getCurrentTenantApiV1TenantsCurrentGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<CurrentTenantResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/tenants/current',
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
     * List all tenants
     * List all org directories. Requires admin access.
     * @returns TenantListResponse Successful Response
     * @throws ApiError
     */
    public static listTenantsEndpointApiV1TenantsGet(): CancelablePromise<TenantListResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/tenants',
        });
    }
    /**
     * Tenant statistics
     * Return database sizes and file counts for a specific tenant.
     * @param orgId
     * @returns TenantStatsResponse Successful Response
     * @throws ApiError
     */
    public static getTenantStatsEndpointApiV1TenantsOrgIdStatsGet(
        orgId: string,
    ): CancelablePromise<TenantStatsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/tenants/{org_id}/stats',
            path: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete tenant data
     * Permanently delete all data for the specified tenant. This operation is irreversible. Requires admin access.
     * @param orgId
     * @returns DeleteTenantResponse Successful Response
     * @throws ApiError
     */
    public static deleteTenantEndpointApiV1TenantsOrgIdDelete(
        orgId: string,
    ): CancelablePromise<DeleteTenantResponse> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/tenants/{org_id}',
            path: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
