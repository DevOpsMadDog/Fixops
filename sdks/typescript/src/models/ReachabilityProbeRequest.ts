/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for reachability probing.
 */
export type ReachabilityProbeRequest = {
    /**
     * Target URLs or host:port to probe
     */
    targets: Array<string>;
    /**
     * CVE being checked for reachability
     */
    cve_id?: string;
    /**
     * Asset IDs for correlation
     */
    asset_ids?: Array<string>;
};

