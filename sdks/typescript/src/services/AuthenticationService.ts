/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DevTokenRequest } from '../models/DevTokenRequest';
import type { DevTokenResponse } from '../models/DevTokenResponse';
import type { DisposableTokenCreate } from '../models/DisposableTokenCreate';
import type { DisposableTokenCreateResponse } from '../models/DisposableTokenCreateResponse';
import type { RoleViewCreate } from '../models/RoleViewCreate';
import type { SSOConfigCreate } from '../models/SSOConfigCreate';
import type { SSOConfigResponse } from '../models/SSOConfigResponse';
import type { SSOConfigUpdate } from '../models/SSOConfigUpdate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AuthenticationService {
    /**
     * Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)
     * Mint a short-lived JWT for dev/Playwright workflows.
     *
     * Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
     * Every successful mint is audit-logged with org_id, role, email, IP.
     * @param requestBody
     * @returns DevTokenResponse Successful Response
     * @throws ApiError
     */
    public static mintDevTokenApiV1AuthDevTokenPost(
        requestBody: DevTokenRequest,
    ): CancelablePromise<DevTokenResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/dev-token',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Sso Config
     * Create a new SSO configuration.
     * @param requestBody
     * @returns SSOConfigResponse Successful Response
     * @throws ApiError
     */
    public static createSsoConfigApiV1AuthSsoPost(
        requestBody: SSOConfigCreate,
    ): CancelablePromise<SSOConfigResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/sso',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Sso Config
     * Get SSO configuration by ID.
     * @param id
     * @returns SSOConfigResponse Successful Response
     * @throws ApiError
     */
    public static getSsoConfigApiV1AuthSsoIdGet(
        id: string,
    ): CancelablePromise<SSOConfigResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/sso/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Sso Config
     * Update SSO configuration.
     * @param id
     * @param requestBody
     * @returns SSOConfigResponse Successful Response
     * @throws ApiError
     */
    public static updateSsoConfigApiV1AuthSsoIdPut(
        id: string,
        requestBody: SSOConfigUpdate,
    ): CancelablePromise<SSOConfigResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/auth/sso/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Revoke Api Key
     * Immediately revoke an API key.
     *
     * AUTHZ-VULN-03: Requires admin/super_admin role.
     * @param keyId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static revokeApiKeyApiV1AuthKeysKeyIdDelete(
        keyId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/auth/keys/{key_id}',
            path: {
                'key_id': keyId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Expiring Keys
     * Get API keys expiring within the specified timeframe.
     *
     * AUTHZ-VULN-03: Requires admin/super_admin role.
     * @param withinDays
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getExpiringKeysApiV1AuthKeysExpiringGet(
        withinDays: number = 7,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/keys/expiring',
            query: {
                'within_days': withinDays,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Cleanup Expired Keys
     * Deactivate all expired keys past their grace period.
     *
     * AUTHZ-VULN-03: Requires admin/super_admin role.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static cleanupExpiredKeysApiV1AuthKeysCleanupPost(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/keys/cleanup',
        });
    }
    /**
     * Get Key Audit Log
     * Get audit trail for a specific API key.
     *
     * AUTHZ-VULN-03: Requires admin/super_admin role.
     * @param keyId
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getKeyAuditLogApiV1AuthKeysKeyIdAuditGet(
        keyId: string,
        limit: number = 100,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/keys/{key_id}/audit',
            path: {
                'key_id': keyId,
            },
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mint Disposable Token Endpoint
     * Mint a disposable scoped token — raw token returned ONCE.
     * @param requestBody
     * @returns DisposableTokenCreateResponse Successful Response
     * @throws ApiError
     */
    public static mintDisposableTokenEndpointApiV1AuthDisposableTokenPost(
        requestBody: DisposableTokenCreate,
    ): CancelablePromise<DisposableTokenCreateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/disposable-token',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Revoke Disposable Token Endpoint
     * Revoke a disposable token in the caller's org.
     * @param tokenId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static revokeDisposableTokenEndpointApiV1AuthDisposableTokenTokenIdDelete(
        tokenId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/auth/disposable-token/{token_id}',
            path: {
                'token_id': tokenId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Disposable Tokens Endpoint
     * List disposable tokens (never returns raw_token/hash). Defaults to caller's org.
     * @param orgId
     * @param activeOnly
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listDisposableTokensEndpointApiV1AuthDisposableTokensGet(
        orgId?: (string | null),
        activeOnly: boolean = true,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/disposable-tokens',
            query: {
                'org_id': orgId,
                'active_only': activeOnly,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Role View Endpoint
     * Get the caller's current active role-view override (or null).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRoleViewEndpointApiV1AuthRoleViewGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/role-view',
        });
    }
    /**
     * Switch Role View Endpoint
     * Switch caller's role view (temporary override).
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static switchRoleViewEndpointApiV1AuthRoleViewPost(
        requestBody: RoleViewCreate,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/role-view',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * End Role View Endpoint
     * End an active role-view override.
     * @param overrideId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static endRoleViewEndpointApiV1AuthRoleViewOverrideIdDelete(
        overrideId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/auth/role-view/{override_id}',
            path: {
                'override_id': overrideId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
