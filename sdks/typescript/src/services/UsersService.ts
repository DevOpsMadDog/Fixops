/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PaginatedUserResponse } from '../models/PaginatedUserResponse';
import type { UserCreate } from '../models/UserCreate';
import type { UserResponse } from '../models/UserResponse';
import type { UserUpdate } from '../models/UserUpdate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class UsersService {
    /**
     * List Users
     * List all users with pagination.
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedUserResponse Successful Response
     * @throws ApiError
     */
    public static listUsersApiV1UsersGet(
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedUserResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/users',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create User
     * Create a new user.
     *
     * AUTHZ-VULN-04: Only admin/super_admin callers may assign privileged roles.
     * Non-admin callers are restricted to non-privileged roles (viewer, developer,
     * security_analyst). Assigning admin/super_admin requires admin:all scope.
     * @param requestBody
     * @returns UserResponse Successful Response
     * @throws ApiError
     */
    public static createUserApiV1UsersPost(
        requestBody: UserCreate,
    ): CancelablePromise<UserResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/users',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get User
     * Get user details by ID.
     * @param id
     * @returns UserResponse Successful Response
     * @throws ApiError
     */
    public static getUserApiV1UsersIdGet(
        id: string,
    ): CancelablePromise<UserResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/users/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update User
     * Update a user.
     *
     * AUTHZ-VULN-04: Only admin callers may promote users to privileged roles.
     * @param id
     * @param requestBody
     * @returns UserResponse Successful Response
     * @throws ApiError
     */
    public static updateUserApiV1UsersIdPut(
        id: string,
        requestBody: UserUpdate,
    ): CancelablePromise<UserResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/users/{id}',
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
     * Delete User
     * Delete a user.
     * @param id
     * @returns void
     * @throws ApiError
     */
    public static deleteUserApiV1UsersIdDelete(
        id: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/users/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
