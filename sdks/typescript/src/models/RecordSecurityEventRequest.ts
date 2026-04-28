/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordSecurityEventRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * API UUID
     */
    api_id: string;
    /**
     * auth_failure | rate_exceeded | injection | schema_violation | bot
     */
    event_type: string;
    /**
     * Attacking source IP
     */
    source_ip: string;
    /**
     * Request path that triggered the event
     */
    request_path?: string;
    /**
     * low | medium | high | critical
     */
    severity?: string;
};

