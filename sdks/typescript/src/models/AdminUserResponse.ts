/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a user.
 */
export type AdminUserResponse = {
    id: string;
    email: string;
    first_name: string;
    last_name: string;
    role: string;
    status: string;
    department: (string | null);
    created_at: string;
    updated_at: string;
    last_login_at: (string | null);
};

