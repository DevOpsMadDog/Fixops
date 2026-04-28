/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__teams_router__AddMemberRequest } from '../models/apps__api__teams_router__AddMemberRequest';
import type { apps__api__teams_router__TeamCreate } from '../models/apps__api__teams_router__TeamCreate';
import type { PaginatedTeamResponse } from '../models/PaginatedTeamResponse';
import type { TeamResponse } from '../models/TeamResponse';
import type { TeamUpdate } from '../models/TeamUpdate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TeamsService {
    /**
     * List Teams
     * List all teams with pagination.
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedTeamResponse Successful Response
     * @throws ApiError
     */
    public static listTeamsApiV1TeamsGet(
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedTeamResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/teams',
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
     * Create Team
     * Create a new team.
     * @param requestBody
     * @returns TeamResponse Successful Response
     * @throws ApiError
     */
    public static createTeamApiV1TeamsPost(
        requestBody: apps__api__teams_router__TeamCreate,
    ): CancelablePromise<TeamResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/teams',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Team
     * Get team details by ID.
     * @param id
     * @returns TeamResponse Successful Response
     * @throws ApiError
     */
    public static getTeamApiV1TeamsIdGet(
        id: string,
    ): CancelablePromise<TeamResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/teams/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Team
     * Update a team.
     * @param id
     * @param requestBody
     * @returns TeamResponse Successful Response
     * @throws ApiError
     */
    public static updateTeamApiV1TeamsIdPut(
        id: string,
        requestBody: TeamUpdate,
    ): CancelablePromise<TeamResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/teams/{id}',
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
     * Delete Team
     * Delete a team.
     * @param id
     * @returns void
     * @throws ApiError
     */
    public static deleteTeamApiV1TeamsIdDelete(
        id: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/teams/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Team Members
     * List all members of a team.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listTeamMembersApiV1TeamsIdMembersGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/teams/{id}/members',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Team Member
     * Add a user to a team.
     * @param id
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addTeamMemberApiV1TeamsIdMembersPost(
        id: string,
        requestBody: apps__api__teams_router__AddMemberRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/teams/{id}/members',
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
     * Remove Team Member
     * Remove a user from a team.
     * @param id
     * @param userId
     * @returns void
     * @throws ApiError
     */
    public static removeTeamMemberApiV1TeamsIdMembersUserIdDelete(
        id: string,
        userId: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/teams/{id}/members/{user_id}',
            path: {
                'id': id,
                'user_id': userId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
