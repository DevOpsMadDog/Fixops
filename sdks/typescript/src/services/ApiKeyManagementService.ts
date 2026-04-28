/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { APIKeyResponse } from '../models/APIKeyResponse';
import type { apps__api__apikey_router__CreateKeyRequest } from '../models/apps__api__apikey_router__CreateKeyRequest';
import type { CreateKeyResponse } from '../models/CreateKeyResponse';
import type { UpdateKeyRequest } from '../models/UpdateKeyRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ApiKeyManagementService {
    /**
     * Create Key
     * Create a new API key. The plaintext key is returned ONCE.
     * @param requestBody
     * @returns CreateKeyResponse Successful Response
     * @throws ApiError
     */
    public static createKeyApiV1AuthKeysPost(
        requestBody: apps__api__apikey_router__CreateKeyRequest,
    ): CancelablePromise<CreateKeyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/keys',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Keys
     * List all API keys for an org (no secrets exposed).
     * @param orgId
     * @returns APIKeyResponse Successful Response
     * @throws ApiError
     */
    public static listKeysApiV1AuthKeysGet(
        orgId: string,
    ): CancelablePromise<Array<APIKeyResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/auth/keys',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Rotate Key
     * Rotate a key — deactivates old, returns new key (plaintext shown once).
     * @param keyId
     * @returns CreateKeyResponse Successful Response
     * @throws ApiError
     */
    public static rotateKeyApiV1AuthKeysKeyIdRotatePost(
        keyId: string,
    ): CancelablePromise<CreateKeyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/auth/keys/{key_id}/rotate',
            path: {
                'key_id': keyId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Key
     * Get a single API key by ID.
     * @param keyId
     * @returns APIKeyResponse Successful Response
     * @throws ApiError
     */
    public static getKeyApiV1AuthKeysKeyIdGet(
        keyId: string,
    ): CancelablePromise<APIKeyResponse> {
        return __request(OpenAPI, {
            method: 'GET',
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
     * Update Key
     * Update mutable key metadata: name, description, scopes, rate_limit.
     * @param keyId
     * @param requestBody
     * @returns APIKeyResponse Successful Response
     * @throws ApiError
     */
    public static updateKeyApiV1AuthKeysKeyIdPut(
        keyId: string,
        requestBody: UpdateKeyRequest,
    ): CancelablePromise<APIKeyResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/auth/keys/{key_id}',
            path: {
                'key_id': keyId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
