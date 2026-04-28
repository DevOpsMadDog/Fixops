/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_threat_protection_router__CreateRuleRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Rule name
     */
    name: string;
    /**
     * Threat type: injection, auth_bypass, rate_abuse, data_scraping, bot_attack, credential_stuffing, parameter_tampering, mass_assignment
     */
    threat_type?: string;
    /**
     * Detection pattern (regex or keyword)
     */
    pattern?: string;
    /**
     * Action: block, rate_limit, challenge, monitor, allow
     */
    action?: string;
    /**
     * Trigger threshold count
     */
    threshold?: number;
    /**
     * Time window in seconds
     */
    window_seconds?: number;
};

