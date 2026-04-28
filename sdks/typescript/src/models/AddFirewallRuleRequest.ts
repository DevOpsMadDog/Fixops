/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddFirewallRuleRequest = {
    /**
     * Descriptive rule name
     */
    rule_name: string;
    /**
     * Source CIDR or 'any'
     */
    src: string;
    /**
     * Destination CIDR or 'any'
     */
    dst: string;
    /**
     * Port number, range, or 'any'
     */
    port: string;
    /**
     * Protocol: tcp, udp, or any
     */
    protocol?: string;
    /**
     * allow or deny
     */
    action?: string;
    org_id?: string;
    bidirectional?: boolean;
    /**
     * Optional expiry timestamp for temporary rules
     */
    expiry?: (string | null);
    metadata?: Record<string, any>;
};

