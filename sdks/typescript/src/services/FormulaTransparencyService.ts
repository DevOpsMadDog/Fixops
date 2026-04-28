/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FormulaHistoryBody } from '../models/FormulaHistoryBody';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class FormulaTransparencyService {
    /**
     * GAP-043: Return full scoring formula transparency
     * @param orgId Organization ID (query parameter, overrides header)
     * @param findingId Optional finding id for contributor values
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static formulaBreakdownApiV1FormulaBreakdownGet(
        orgId?: (string | null),
        findingId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/formula/breakdown',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
                'finding_id': findingId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * GAP-043: Register a scoring-formula change for audit
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static formulaHistoryCreateApiV1FormulaHistoryPost(
        requestBody: FormulaHistoryBody,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/formula/history',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * GAP-043: List scoring-formula change history
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static formulaHistoryListApiV1FormulaHistoryGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/formula/history',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
