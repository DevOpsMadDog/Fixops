/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_enforcement_router__CreatePolicyRequest = {
    /**
     * Human-readable policy name
     */
    policy_name: string;
    /**
     * application | api | database | network_segment | cloud_service
     */
    resource_type?: string;
    /**
     * allow | deny | mfa_required | device_check_required
     */
    action: string;
    /**
     * user | group | service_account | device
     */
    principal_type?: string;
    /**
     * Conditions: min_trust_score, require_mfa, allowed_locations, allowed_device_types, time_restrictions
     */
    conditions?: Record<string, any>;
    /**
     * 1=highest, 100=lowest
     */
    priority?: number;
};

