/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { UserResponse } from './UserResponse';
/**
 * Paginated user response.
 */
export type PaginatedUserResponse = {
    items: Array<UserResponse>;
    total: number;
    limit: number;
    offset: number;
};

