/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_threat_protection_router__RecordEventRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Associated rule id (optional)
     */
    rule_id?: string;
    /**
     * Threat type that was detected
     */
    threat_type?: string;
    /**
     * Attacker source IP address
     */
    source_ip?: string;
    /**
     * Targeted API endpoint
     */
    endpoint?: string;
    /**
     * HTTP method
     */
    method?: string;
    /**
     * SHA-256 hash of request payload
     */
    payload_hash?: string;
    /**
     * Action taken by the system
     */
    action_taken?: string;
    /**
     * Event severity
     */
    severity?: string;
};

