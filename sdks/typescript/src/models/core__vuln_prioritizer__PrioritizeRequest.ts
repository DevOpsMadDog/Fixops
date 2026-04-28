/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to trigger re-prioritization.
 */
export type core__vuln_prioritizer__PrioritizeRequest = {
    org_id?: string;
    asset_ids?: (Array<string> | null);
    force_epss_refresh?: boolean;
};

