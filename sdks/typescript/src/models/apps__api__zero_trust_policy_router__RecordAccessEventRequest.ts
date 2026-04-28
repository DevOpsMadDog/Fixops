/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_policy_router__RecordAccessEventRequest = {
    /**
     * User identifier
     */
    user?: string;
    /**
     * Device identifier
     */
    device?: string;
    /**
     * Resource accessed
     */
    resource?: string;
    /**
     * allow | deny | mfa_required
     */
    decision?: string;
    /**
     * Policy that matched
     */
    policy_id?: (string | null);
    /**
     * Source IP address
     */
    source_ip?: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

