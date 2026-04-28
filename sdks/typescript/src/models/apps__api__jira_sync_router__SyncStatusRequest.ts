/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__jira_sync_router__SyncStatusRequest = {
    /**
     * Finding to update
     */
    finding_id: string;
    /**
     * New finding status, e.g. resolved, closed, in_progress
     */
    new_status: string;
};

