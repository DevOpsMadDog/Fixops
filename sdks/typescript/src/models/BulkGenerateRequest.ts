/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to generate fixes for multiple findings.
 */
export type BulkGenerateRequest = {
    /**
     * List of finding dicts
     */
    findings: Array<Record<string, any>>;
    repo_context?: (Record<string, any> | null);
};

