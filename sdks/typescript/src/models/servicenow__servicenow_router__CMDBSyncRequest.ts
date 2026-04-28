/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type servicenow__servicenow_router__CMDBSyncRequest = {
    /**
     * Connection ID to sync from
     */
    connection_id: string;
    /**
     * CI class names to pull
     */
    ci_classes?: Array<string>;
    /**
     * ServiceNow encoded query filter
     */
    query?: string;
    /**
     * Max CIs per class
     */
    limit?: number;
};

