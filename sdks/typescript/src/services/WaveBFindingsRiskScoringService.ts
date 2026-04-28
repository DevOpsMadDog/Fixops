/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveBFindingsRiskScoringService {
    /**
     * Wave-B-03 — Filterable findings list
     * List findings with rich filtering.
     *
     * Lifecycle terms (``new``, ``unchanged``, ``resolved``) are mapped to the
     * engine's stored ``status`` column.
     * @param status Lifecycle status filter (new|unchanged|resolved) or canonical engine status (open|in-progress|...)
     * @param severity
     * @param sourceTool
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listFindingsApiV1FindingsGet(
        status?: (string | null),
        severity?: (string | null),
        sourceTool?: (string | null),
        limit: number = 500,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/findings',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'status': status,
                'severity': severity,
                'source_tool': sourceTool,
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
