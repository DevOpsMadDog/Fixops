/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DCAParseRepoRequest } from '../models/DCAParseRepoRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveADeepCodeAnalysisService {
    /**
     * Run Deep Code Analysis (DCA) on a repository
     * Parse a repository into entities (functions, classes, modules).
     *
     * Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
     * when the repo is local + Python; otherwise records a parse-request that
     * a worker can pick up later.
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dcaParseRepoApiV1DcaParseRepoPost(
        requestBody: DCAParseRepoRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/dca/parse-repo',
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
     * List parsed entities (functions, classes) for a repo
     * Return entities recorded for a repo.
     *
     * Pulls from the ``function_reachability_engine`` SQLite tables when the
     * parser populated them; otherwise returns the entity_counts persisted by
     * /parse-repo.
     * @param repo
     * @param kind function|class|module
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dcaEntitiesApiV1DcaEntitiesRepoGet(
        repo: string,
        kind?: (string | null),
        limit: number = 200,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dca/entities/{repo}',
            path: {
                'repo': repo,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'kind': kind,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Diff DCA entity sets between two parse runs
     * Diff entity sets between two parse runs (`from` → `to` revisions).
     * @param repo
     * @param from
     * @param to
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dcaDiffApiV1DcaDiffGet(
        repo: string,
        from: string,
        to: string,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/dca/diff',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'repo': repo,
                'from': from,
                'to': to,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
