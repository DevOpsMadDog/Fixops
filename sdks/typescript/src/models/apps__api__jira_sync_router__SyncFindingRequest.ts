/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__jira_sync_router__SyncFindingRequest = {
    /**
     * Unique finding identifier
     */
    finding_id: string;
    /**
     * Finding fields: title, severity, description, cve_id, source, etc.
     */
    finding_data: Record<string, any>;
};

