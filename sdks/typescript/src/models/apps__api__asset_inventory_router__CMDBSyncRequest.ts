/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__asset_inventory_router__CMDBSyncRequest = {
    /**
     * CMDB system name (e.g. ServiceNow, Jira)
     */
    cmdb_system: string;
    /**
     * Asset ID in the external CMDB
     */
    external_id: string;
    changes?: Record<string, any>;
};

