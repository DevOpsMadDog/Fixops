/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SystemHealthService {
    /**
     * Full system health report
     * Return a full system health report aggregating all subsystems.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSystemHealthApiV1SystemHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/system/health',
        });
    }
}
