/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to generate autofix for a remediation task.
 */
export type AutoFixTaskRequest = {
    source_code?: (string | null);
    repo_context?: (Record<string, any> | null);
    repository?: (string | null);
    create_pr?: boolean;
};

