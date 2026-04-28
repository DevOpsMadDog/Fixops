/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_surface_manager_router__TriggerScanRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Optional discovery data to ingest during scan
     */
    discovery_data?: null;
    /**
     * CMDB inventory for shadow IT comparison
     */
    cmdb_names?: (Array<string> | null);
};

