/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ReportsGapService {
    /**
     * List Report Templates
     * List available report templates from ReportDB.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listReportTemplatesApiV1ReportsTemplatesGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/reports/templates',
        });
    }
}
