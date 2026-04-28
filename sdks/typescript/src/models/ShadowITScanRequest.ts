/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ShadowITScanRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Approved asset names from CMDB
     */
    cmdb_names?: (Array<string> | null);
    /**
     * Extra names from network discovery
     */
    discovered_names?: (Array<string> | null);
};

