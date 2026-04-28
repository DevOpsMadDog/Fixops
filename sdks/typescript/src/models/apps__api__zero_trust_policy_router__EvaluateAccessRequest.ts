/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_policy_router__EvaluateAccessRequest = {
    /**
     * User identifier
     */
    user?: string;
    /**
     * Device identifier
     */
    device?: string;
    /**
     * Source IP address
     */
    source_ip?: string;
    /**
     * Destination resource or host
     */
    destination?: string;
    /**
     * Resource being accessed
     */
    resource?: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

