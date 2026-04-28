/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for counterfactual analysis.
 */
export type api__algorithmic_router__CounterfactualRequest = {
    /**
     * Whether an exploit is available
     */
    has_exploit?: boolean;
    /**
     * Whether vulnerable code is reachable
     */
    is_reachable?: boolean;
    /**
     * Whether exposed to internet
     */
    is_internet_facing?: boolean;
    /**
     * Whether WAF is enabled
     */
    has_waf?: boolean;
    /**
     * Whether vulnerability is patched
     */
    is_patched?: boolean;
    /**
     * Whether authentication is required
     */
    has_auth?: boolean;
    /**
     * Proposed intervention: patch, enable_waf, add_auth, etc.
     */
    intervention: string;
};

