/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DiscoverFromFindingsRequest = {
    /**
     * Pipeline findings to extract assets from
     */
    findings: Array<Record<string, any>>;
    org_id?: string;
    /**
     * Source: cloud_discovery, k8s_scan, container_scan, network_scan, api_scan, manual
     */
    discovery_source?: string;
};

