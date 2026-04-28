/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_router__CreatePolicyRequest = {
    /**
     * Human-readable policy name
     */
    name: string;
    /**
     * Policy conditions: min_trust_level, require_mfa, allowed_networks, allowed_time_ranges, require_compliant_device, max_risk_score
     */
    conditions?: Record<string, any>;
    /**
     * allow | deny | step_up_auth | quarantine | monitor
     */
    action: string;
    /**
     * Lower = higher priority
     */
    priority?: number;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

