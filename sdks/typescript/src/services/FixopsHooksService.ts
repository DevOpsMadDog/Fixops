/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HookUninstallRequest } from '../models/HookUninstallRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class FixopsHooksService {
    /**
     * Uninstall an active hook policy (delete by id, hash, or org)
     * Delete an active hook policy and emit an audit tombstone.
     *
     * Resolution order:
     * 1. ``hook_id`` — exact policy record id
     * 2. ``policy_hash`` + org — content-addressed delete
     * 3. ``org_id`` alone — uninstall the *active* (most recent) policy for that org
     *
     * Returns: deleted_count, deleted record metadata, tombstone id.
     * Raises 404 if nothing matches, 422 if no resolver fields supplied.
     * @param requestBody
     * @param xOrgId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static uninstallHookApiV1HooksUninstallPost(
        requestBody: HookUninstallRequest,
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/hooks/uninstall',
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
}
