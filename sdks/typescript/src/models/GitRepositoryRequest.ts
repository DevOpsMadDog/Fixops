/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Git repository configuration.
 */
export type GitRepositoryRequest = {
    /**
     * Repository URL
     */
    url: string;
    /**
     * Branch to analyze
     */
    branch?: string;
    /**
     * Specific commit to analyze
     */
    commit?: (string | null);
    /**
     * Authentication token
     */
    auth_token?: (string | null);
    /**
     * Username for authentication
     */
    auth_username?: (string | null);
    /**
     * Password for authentication
     */
    auth_password?: (string | null);
};

