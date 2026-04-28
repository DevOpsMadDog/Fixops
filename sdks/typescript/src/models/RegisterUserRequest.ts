/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterUserRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Unique username within the org
     */
    username: string;
    /**
     * User's department
     */
    department?: string;
    /**
     * User's job role
     */
    role?: string;
    /**
     * Manager's username or ID
     */
    manager?: string;
    /**
     * active | suspended | terminated
     */
    status?: string;
    /**
     * ISO-8601 datetime of last activity
     */
    last_seen?: (string | null);
};

