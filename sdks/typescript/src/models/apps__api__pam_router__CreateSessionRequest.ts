/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__pam_router__CreateSessionRequest = {
    account_id: string;
    requester?: string;
    justification?: string;
    /**
     * One of: interactive, api, scheduled
     */
    session_type?: string;
    target_system?: string;
    requested_duration_minutes?: number;
    started_at?: (string | null);
    recording_enabled?: boolean;
};

