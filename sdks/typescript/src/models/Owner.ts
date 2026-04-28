/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A code owner — a person or team responsible for one or more file paths.
 */
export type Owner = {
    /**
     * Unique identifier / contact email
     */
    email: string;
    /**
     * Human-readable display name
     */
    name: string;
    /**
     * Team or squad name
     */
    team: string;
    /**
     * Repos this owner is responsible for
     */
    repos?: Array<string>;
    /**
     * Glob patterns for files this owner is responsible for
     */
    file_patterns?: Array<string>;
    created_at?: string;
};

