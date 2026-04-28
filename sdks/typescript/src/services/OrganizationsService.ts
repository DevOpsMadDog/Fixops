/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class OrganizationsService {
    /**
     * List Orgs
     * List all known organisations.
     *
     * Returns registered orgs plus any org_ids discovered by scanning engine
     * SQLite databases (when ``include_discovered=true``).
     * @param includeDiscovered Include org_ids discovered from engine databases
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listOrgsApiV1OrgsGet(
        includeDiscovered: boolean = true,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/orgs',
            query: {
                'include_discovered': includeDiscovered,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Org Summary
     * Return a dashboard summary for a specific org.
     *
     * Shows how many engine databases contain data for this org_id and the
     * total row count across all tables.
     * @param orgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getOrgSummaryApiV1OrgsOrgIdSummaryGet(
        orgId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/orgs/{org_id}/summary',
            path: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
