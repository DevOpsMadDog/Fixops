/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__correlation_router__AnalyzeRequest } from '../models/apps__api__correlation_router__AnalyzeRequest';
import type { apps__api__correlation_router__StatusUpdateRequest } from '../models/apps__api__correlation_router__StatusUpdateRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class CorrelationsService {
    /**
     * Run correlation on provided findings
     * Run all correlation strategies on the supplied findings list.
     *
     * Optionally also builds and persists Exposure Cases from the correlations.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyzeFindingsApiV1CorrelationsAnalyzePost(
        requestBody: apps__api__correlation_router__AnalyzeRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/correlations/analyze',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Exposure Cases
     * List persisted Exposure Cases with optional filters.
     * @param orgId Filter by org
     * @param status Filter by status: open | investigating | resolved
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listExposureCasesApiV1CorrelationsExposureCasesGet(
        orgId?: (string | null),
        status?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/correlations/exposure-cases',
            query: {
                'org_id': orgId,
                'status': status,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Exposure Case detail
     * Retrieve a single Exposure Case by ID.
     * @param caseId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getExposureCaseApiV1CorrelationsExposureCasesCaseIdGet(
        caseId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/correlations/exposure-cases/{case_id}',
            path: {
                'case_id': caseId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Exposure Case investigation status
     * Change the investigation status of an Exposure Case.
     * @param caseId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut(
        caseId: string,
        requestBody: apps__api__correlation_router__StatusUpdateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/correlations/exposure-cases/{case_id}/status',
            path: {
                'case_id': caseId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Correlation statistics
     * Return correlation statistics: reduction ratio, avg findings per case, etc.
     * @param orgId Filter by org
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1CorrelationsStatsGet(
        orgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/correlations/stats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
