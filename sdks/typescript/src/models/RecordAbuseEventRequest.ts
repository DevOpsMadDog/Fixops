/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAbuseEventRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Abuse event type (bola, injection, auth_bypass, etc.)
     */
    event_type: string;
    /**
     * one of: critical/high/medium/low
     */
    severity?: string;
    /**
     * Source IP address
     */
    source_ip?: string;
    /**
     * Associated API key ID if known
     */
    api_key_id?: string;
    /**
     * Associated endpoint ID if known
     */
    endpoint_id?: string;
    /**
     * Sanitised request payload preview
     */
    request_payload_preview?: string;
    /**
     * one of: detected/investigating/blocked/false_positive
     */
    status?: string;
};

