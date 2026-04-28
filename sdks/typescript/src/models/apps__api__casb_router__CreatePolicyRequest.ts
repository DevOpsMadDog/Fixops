/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__casb_router__CreatePolicyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Policy name
     */
    name: string;
    /**
     * Policy type: data_loss/app_block/oauth_restrict
     */
    policy_type: string;
    /**
     * Policy condition parameters
     */
    conditions?: Record<string, any>;
    /**
     * Enforcement action: block/alert/encrypt
     */
    action?: string;
};

