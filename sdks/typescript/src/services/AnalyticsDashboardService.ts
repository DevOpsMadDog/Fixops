/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AnalyticsDashboardService {
    /**
     * Get Mttr
     * Mean time to remediate (hours) — average time from first opened to resolved.
     * @param orgId Organisation identifier
     * @param severity Filter by severity (critical/high/medium/low/info)
     * @param periodDays Look-back window in days
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMttrApiV1AnalyticsMttrGet(
        orgId: string = 'default',
        severity?: (string | null),
        periodDays: number = 30,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/analytics/mttr',
            query: {
                'org_id': orgId,
                'severity': severity,
                'period_days': periodDays,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
