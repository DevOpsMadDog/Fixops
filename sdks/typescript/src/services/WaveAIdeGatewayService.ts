/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IDEAuthenticateTokenRequest } from '../models/IDEAuthenticateTokenRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WaveAIdeGatewayService {
    /**
     * List IDE-relevant findings filtered by repo+file
     * Return findings scoped to a (repo, file) pair for IDE in-line overlay.
     * @param repo
     * @param file
     * @param severity
     * @param limit
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ideFindingsApiV1IdeFindingsGet(
        repo: string,
        file: string,
        severity?: (string | null),
        limit: number = 100,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ide/findings',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'repo': repo,
                'file': file,
                'severity': severity,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Validate an IDE-supplied token and return scoped session info
     * Validate an IDE token and return session info.
     *
     * Honors three lookup paths in order:
     * 1. JWT decode via core.api_key_manager / FIXOPS_JWT_SECRET
     * 2. api_key_manager.validate_key by raw key
     * 3. Fallback failure with 401
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ideAuthenticateTokenApiV1IdeAuthenticateTokenPost(
        requestBody: IDEAuthenticateTokenRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ide/authenticate-token',
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
     * Snapshot of a user's IDE state — recent findings, open files, scopes
     * Return per-user IDE snapshot: recent files, scopes, finding counts.
     * @param userId
     * @param repo
     * @param xOrgId
     * @param xUserId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ideUserSnapshotApiV1IdeUserSnapshotGet(
        userId: string = 'self',
        repo?: (string | null),
        xOrgId?: (string | null),
        xUserId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ide/user-snapshot',
            headers: {
                'X-Org-ID': xOrgId,
                'X-User-ID': xUserId,
            },
            query: {
                'user_id': userId,
                'repo': repo,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
