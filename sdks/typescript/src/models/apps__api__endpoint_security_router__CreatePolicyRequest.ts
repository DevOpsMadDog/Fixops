/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__endpoint_security_router__CreatePolicyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Policy name
     */
    name: string;
    /**
     * Policy description
     */
    description?: string;
    /**
     * Policy rules (JSON)
     */
    rules?: Record<string, any>;
    /**
     * Whether the policy is active
     */
    enabled?: boolean;
};

