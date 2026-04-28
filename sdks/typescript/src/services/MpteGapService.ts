/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MpteGapService {
    /**
     * Get Mpte Monitoring
     * Get MPTE monitoring data from the real MPTE database.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMpteMonitoringApiV1MpteMonitoringGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mpte/monitoring',
        });
    }
}
