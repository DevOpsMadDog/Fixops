/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GrantAccessBody = {
    /**
     * Target system name
     */
    system_name: string;
    /**
     * Role to grant
     */
    role: string;
    /**
     * read | write | admin | owner
     */
    access_level?: string;
    /**
     * ISO datetime for expiry (empty = never)
     */
    expires_at?: string;
    /**
     * Approver username or ID
     */
    granted_by?: string;
};

