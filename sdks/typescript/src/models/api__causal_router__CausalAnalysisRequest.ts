/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for causal vulnerability analysis.
 */
export type api__causal_router__CausalAnalysisRequest = {
    has_exploit?: boolean;
    is_reachable?: boolean;
    is_internet_facing?: boolean;
    has_waf?: boolean;
    is_patched?: boolean;
    has_auth?: boolean;
};

