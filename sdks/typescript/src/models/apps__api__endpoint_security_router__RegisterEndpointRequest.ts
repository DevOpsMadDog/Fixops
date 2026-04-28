/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__endpoint_security_router__RegisterEndpointRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Endpoint hostname
     */
    hostname: string;
    /**
     * IP address
     */
    ip?: string;
    /**
     * Operating system
     */
    os?: string;
    /**
     * EDR agent version
     */
    agent_version?: string;
    /**
     * active or inactive
     */
    status?: string;
    /**
     * Risk score 0–100
     */
    risk_score?: number;
    /**
     * ISO-8601 timestamp of last check-in
     */
    last_seen?: string;
    /**
     * Assigned policy ID
     */
    policy_id?: string;
};

