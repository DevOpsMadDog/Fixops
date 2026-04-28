/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddFlowRequest } from '../models/AddFlowRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class NetworkSegmentationService {
    /**
     * Add Flow
     * Record an observed network flow between two zones.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addFlowApiV1NetworkFlowsPost(
        requestBody: AddFlowRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/network/flows',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Flows
     * List recorded network flows.
     * @param allowed Filter by allowed status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listFlowsApiV1NetworkFlowsGet(
        allowed?: (boolean | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/network/flows',
            query: {
                'allowed': allowed,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
