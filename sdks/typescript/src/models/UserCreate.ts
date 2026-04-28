/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { UserRole } from './UserRole';
/**
 * Request model for creating a user.
 */
export type UserCreate = {
    /**
     * User email
     */
    email: string;
    /**
     * User password
     */
    password: string;
    first_name: string;
    last_name: string;
    role?: UserRole;
    department?: (string | null);
};

