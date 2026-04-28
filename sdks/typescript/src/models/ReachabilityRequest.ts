/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for reachability analysis.
 */
export type ReachabilityRequest = {
    cve_id: string;
    asset_ids: Array<string>;
    /**
     * shallow, medium, deep
     */
    depth?: string;
};

