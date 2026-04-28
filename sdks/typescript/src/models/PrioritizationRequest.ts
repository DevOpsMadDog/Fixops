/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for vulnerability prioritization.
 */
export type PrioritizationRequest = {
    finding_ids?: Array<string>;
    /**
     * ssvc, epss, cvss, custom
     */
    algorithm?: string;
    business_context?: (Record<string, any> | null);
};

