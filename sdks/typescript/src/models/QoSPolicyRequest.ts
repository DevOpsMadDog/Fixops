/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type QoSPolicyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Policy name
     */
    name: string;
    /**
     * QoS priority 1 (highest) to 8 (lowest)
     */
    priority?: number;
    /**
     * Traffic class, e.g. 'voice', 'bulk', 'critical'
     */
    traffic_class?: string;
    /**
     * Bandwidth cap 0-100%
     */
    bandwidth_limit_pct?: number;
};

