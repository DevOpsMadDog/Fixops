/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class VersionService {
    /**
     * API version information
     * Return API version metadata.
     *
     * Response fields:
     * - **version**: Semantic version of the ALDECI API (e.g. ``1.0.0``)
     * - **build_date**: Date the current build was produced (``YYYY-MM-DD``)
     * - **git_commit**: Short git SHA of the deployed revision
     * - **deprecated_endpoints**: Count of currently deprecated API paths
     * - **timestamp**: UTC timestamp of this response
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getVersionApiV1VersionGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/version',
        });
    }
}
