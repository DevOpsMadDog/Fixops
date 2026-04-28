/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DefaultService {
    /**
     * Authenticated Status
     * Authenticated status endpoint.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static authenticatedStatusApiV1StatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/status',
        });
    }
    /**
     * Global Search
     * Cross-entity global search across findings, assets, evidence, and tickets.
     *
     * Returns unified results sorted by relevance with type annotations so the
     * UI can render heterogeneous result cards in a single list.
     * @param q Search query
     * @param entityTypes Comma-separated entity types to search: findings,assets,evidence,tickets. Default: all.
     * @param limit Max results per entity type
     * @returns any Successful Response
     * @throws ApiError
     */
    public static globalSearchApiV1SearchGet(
        q: string = '',
        entityTypes?: (string | null),
        limit: number = 50,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/search',
            query: {
                'q': q,
                'entity_types': entityTypes,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
