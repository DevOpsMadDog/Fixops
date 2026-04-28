/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /suggest-version.
 */
export type SuggestVersionRequest = {
    /**
     * Raw commit log text
     */
    commits: string;
    /**
     * Current semver string
     */
    current_version?: string;
};

