/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_connectors_router__HealthResponse = {
    provider: string;
    account_id: string;
    label: string;
    status: string;
    last_sync_at?: (string | null);
    last_error?: (string | null);
    error_count?: number;
    consecutive_errors?: number;
    credential_expired?: boolean;
    resources_synced?: number;
    findings_synced?: number;
};

