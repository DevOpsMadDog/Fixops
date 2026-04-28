/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { OrgCreate } from '../models/OrgCreate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class OrgHierarchyService {
    /**
     * Create Org
     * Create an organisation node.
     * @param orgId Tenant ID
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createOrgApiV1OrgsPost(
        orgId: string,
        requestBody: OrgCreate,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/orgs',
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
}
