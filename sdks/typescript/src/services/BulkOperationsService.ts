/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__bulk_operations_router__ExportRequest } from '../models/apps__api__bulk_operations_router__ExportRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class BulkOperationsService {
    /**
     * Export Findings
     * Export org findings to CSV, JSON, or SARIF.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportFindingsApiV1BulkExportPost(
        requestBody: apps__api__bulk_operations_router__ExportRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/bulk/export',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
