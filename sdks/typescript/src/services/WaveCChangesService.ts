/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveCChangesService {
    /**
     * List material change events (filter by kind/severity)
     * Query the material change ledger with optional filters.
     * @param orgId
     * @param kind dependency|config|secret|crypto|infra|rbac|other
     * @param severity critical|high|medium|low|info
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static changesMaterialApiV1ChangesMaterialGet(
        orgId: string = 'default',
        kind?: (string | null),
        severity?: (string | null),
        limit: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/changes/material',
            query: {
                'org_id': orgId,
                'kind': kind,
                'severity': severity,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
