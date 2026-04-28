/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LoginRequest } from '../models/LoginRequest';
import type { LoginResponse } from '../models/LoginResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class UsersPublicService {
    /**
     * Login
     * Authenticate user and return JWT token.
     *
     * Features:
     * - Rate limiting to prevent brute force attacks
     * - Secure JWT token generation
     * - Audit logging
     * @param requestBody
     * @returns LoginResponse Successful Response
     * @throws ApiError
     */
    public static loginApiV1UsersLoginPost(
        requestBody: LoginRequest,
    ): CancelablePromise<LoginResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/users/login',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Logout
     * Logout — revoke the current JWT by adding its jti to the server-side blocklist.
     *
     * AUTH-VULN-06: Server-side session revocation on logout.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static logoutApiV1UsersLogoutPost(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/users/logout',
        });
    }
}
