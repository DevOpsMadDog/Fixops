/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { UserRole } from './UserRole';
import type { UserStatus } from './UserStatus';
/**
 * Request model for updating a user.
 */
export type UserUpdate = {
    first_name?: (string | null);
    last_name?: (string | null);
    role?: (UserRole | null);
    status?: (UserStatus | null);
    department?: (string | null);
};

