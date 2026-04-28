/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for auto-fix endpoint.
 */
export type FixRequest = {
    /**
     * If true, report what would be fixed without writing to the database.
     */
    dry_run?: boolean;
    /**
     * Limit fixes to these issue types (orphan, duplicate). None = all fixable.
     */
    issue_types?: (Array<string> | null);
};

