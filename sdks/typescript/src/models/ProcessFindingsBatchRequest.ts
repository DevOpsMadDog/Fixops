/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to process a batch of findings.
 */
export type ProcessFindingsBatchRequest = {
    findings: Array<Record<string, any>>;
    run_id: string;
    org_id: string;
    source?: string;
};

