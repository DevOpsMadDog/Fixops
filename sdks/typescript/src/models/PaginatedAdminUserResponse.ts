/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AdminUserResponse } from './AdminUserResponse';
/**
 * Paginated user response.
 */
export type PaginatedAdminUserResponse = {
    items: Array<AdminUserResponse>;
    total: number;
    limit: number;
    offset: number;
};

