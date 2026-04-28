/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AdminTeamCreate } from '../models/AdminTeamCreate';
import type { AdminTeamResponse } from '../models/AdminTeamResponse';
import type { AdminTeamUpdate } from '../models/AdminTeamUpdate';
import type { AdminUserCreate } from '../models/AdminUserCreate';
import type { AdminUserResponse } from '../models/AdminUserResponse';
import type { AdminUserUpdate } from '../models/AdminUserUpdate';
import type { PaginatedAdminTeamResponse } from '../models/PaginatedAdminTeamResponse';
import type { PaginatedAdminUserResponse } from '../models/PaginatedAdminUserResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AdminService {
    /**
     * List all users
     * List all users with pagination. Requires admin scope.
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedAdminUserResponse Successful Response
     * @throws ApiError
     */
    public static adminListUsersApiV1AdminUsersGet(
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedAdminUserResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/admin/users',
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
     * Create user
     * Create a new user. Requires admin scope.
     * @param requestBody
     * @returns AdminUserResponse Successful Response
     * @throws ApiError
     */
    public static adminCreateUserApiV1AdminUsersPost(
        requestBody: AdminUserCreate,
    ): CancelablePromise<AdminUserResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/admin/users',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get user
     * Get user details by ID. Requires admin scope.
     * @param userId
     * @returns AdminUserResponse Successful Response
     * @throws ApiError
     */
    public static adminGetUserApiV1AdminUsersUserIdGet(
        userId: string,
    ): CancelablePromise<AdminUserResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/admin/users/{user_id}',
            path: {
                'user_id': userId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update user
     * Update a user. Requires admin scope.
     * @param userId
     * @param requestBody
     * @returns AdminUserResponse Successful Response
     * @throws ApiError
     */
    public static adminUpdateUserApiV1AdminUsersUserIdPut(
        userId: string,
        requestBody: AdminUserUpdate,
    ): CancelablePromise<AdminUserResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/admin/users/{user_id}',
            path: {
                'user_id': userId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete user
     * Delete a user. Requires admin scope.
     * @param userId
     * @returns void
     * @throws ApiError
     */
    public static adminDeleteUserApiV1AdminUsersUserIdDelete(
        userId: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/admin/users/{user_id}',
            path: {
                'user_id': userId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all teams
     * List all teams with pagination. Requires admin scope.
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedAdminTeamResponse Successful Response
     * @throws ApiError
     */
    public static adminListTeamsApiV1AdminTeamsGet(
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedAdminTeamResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/admin/teams',
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
     * Create team
     * Create a new team. Requires admin scope.
     * @param requestBody
     * @returns AdminTeamResponse Successful Response
     * @throws ApiError
     */
    public static adminCreateTeamApiV1AdminTeamsPost(
        requestBody: AdminTeamCreate,
    ): CancelablePromise<AdminTeamResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/admin/teams',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get team
     * Get team details by ID. Requires admin scope.
     * @param teamId
     * @returns AdminTeamResponse Successful Response
     * @throws ApiError
     */
    public static adminGetTeamApiV1AdminTeamsTeamIdGet(
        teamId: string,
    ): CancelablePromise<AdminTeamResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/admin/teams/{team_id}',
            path: {
                'team_id': teamId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update team
     * Update a team. Requires admin scope.
     * @param teamId
     * @param requestBody
     * @returns AdminTeamResponse Successful Response
     * @throws ApiError
     */
    public static adminUpdateTeamApiV1AdminTeamsTeamIdPut(
        teamId: string,
        requestBody: AdminTeamUpdate,
    ): CancelablePromise<AdminTeamResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/admin/teams/{team_id}',
            path: {
                'team_id': teamId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete team
     * Delete a team. Requires admin scope.
     * @param teamId
     * @returns void
     * @throws ApiError
     */
    public static adminDeleteTeamApiV1AdminTeamsTeamIdDelete(
        teamId: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/admin/teams/{team_id}',
            path: {
                'team_id': teamId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
