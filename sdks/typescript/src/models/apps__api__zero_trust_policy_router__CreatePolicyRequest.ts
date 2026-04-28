/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_policy_router__CreatePolicyRequest = {
    /**
     * Human-readable policy name
     */
    name: string;
    /**
     * Optional description
     */
    description?: string;
    /**
     * network | identity | device | application
     */
    policy_type?: string;
    /**
     * allow | deny | mfa_required
     */
    action?: string;
    /**
     * Source-side match conditions (user, device, source_ip)
     */
    source_conditions?: Record<string, any>;
    /**
     * Destination-side match conditions (resource, destination)
     */
    destination_conditions?: Record<string, any>;
    /**
     * Lower = higher priority
     */
    priority?: number;
    /**
     * Whether this policy is active
     */
    enabled?: boolean;
};

