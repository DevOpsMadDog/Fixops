/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Batch-generate PRs from multiple security findings.
 */
export type BatchGeneratePRRequest = {
    /**
     * List of security findings
     */
    findings: Array<Record<string, any>>;
    repo: string;
    owner: string;
    org_id?: string;
};

