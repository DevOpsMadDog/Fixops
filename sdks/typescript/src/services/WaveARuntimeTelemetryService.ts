/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RuntimeMapToCodeRequest } from '../models/RuntimeMapToCodeRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveARuntimeTelemetryService {
    /**
     * Map a runtime telemetry event to source code locations
     * Resolve a runtime event/stack-trace to candidate code locations.
     *
     * Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
     * is provided; otherwise ingests the supplied stack trace and matches it.
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runtimeMapToCodeApiV1RuntimeMapToCodePost(
        requestBody: RuntimeMapToCodeRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/runtime/map-to-code',
            headers: {
                'X-Org-ID': xOrgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Return runtime traffic stats for an API path
     * Return aggregate runtime traffic for an API path.
     *
     * Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.
     * @param api
     * @param windowMinutes
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runtimeTrafficApiV1RuntimeTrafficApiGet(
        api: string,
        windowMinutes: number = 60,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/runtime/traffic/{api}',
            path: {
                'api': api,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'window_minutes': windowMinutes,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
