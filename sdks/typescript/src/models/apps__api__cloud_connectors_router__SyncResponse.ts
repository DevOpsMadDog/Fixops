/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_connectors_router__SyncResponse = {
    sync_id: string;
    provider: string;
    account_id: string;
    started_at: string;
    completed_at?: (string | null);
    status: string;
    resources_found?: number;
    findings_found?: number;
    error?: (string | null);
};

