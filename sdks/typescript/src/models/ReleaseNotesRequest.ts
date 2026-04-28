/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /release-notes.
 */
export type ReleaseNotesRequest = {
    /**
     * Raw commit log text
     */
    commits: string;
    /**
     * Version label
     */
    version?: string;
};

