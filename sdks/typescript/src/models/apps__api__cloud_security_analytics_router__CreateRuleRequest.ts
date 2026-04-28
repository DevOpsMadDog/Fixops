/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_security_analytics_router__CreateRuleRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Rule name
     */
    rule_name: string;
    /**
     * detection/compliance/baseline/anomaly
     */
    rule_type?: string;
    /**
     * Rule condition expression
     */
    condition?: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * Applicable event sources
     */
    event_sources?: Array<string>;
    /**
     * Whether the rule is active
     */
    enabled?: boolean;
};

