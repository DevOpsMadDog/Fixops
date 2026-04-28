/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Fired when a canary token is accessed / used.
 */
export type CanaryAlert = {
    id?: string;
    canary_id: string;
    triggered_at?: string;
    source_ip: string;
    user_agent?: string;
    request_headers?: Record<string, string>;
    org_id: string;
    severity?: string;
};

