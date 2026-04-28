/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AuditGapService {
    /**
     * Get Audit Trail
     * Get audit trail — alias for list audit logs, formatted for compliance view.
     * @param page
     * @param perPage
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAuditTrailApiV1AuditTrailGet(
        page: number = 1,
        perPage: number = 50,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/audit/trail',
            query: {
                'page': page,
                'per_page': perPage,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
