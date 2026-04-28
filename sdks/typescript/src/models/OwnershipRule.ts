/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A CODEOWNERS-style rule: glob pattern → owner email with priority.
 */
export type OwnershipRule = {
    id?: string;
    /**
     * Glob pattern (e.g. 'src/core**')
     */
    pattern: string;
    /**
     * Email of the assigned owner
     */
    owner_email: string;
    /**
     * Higher priority rules win when multiple patterns match
     */
    priority?: number;
    created_at?: string;
};

