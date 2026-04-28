/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__soc_triage_router__CreateRuleRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Unique rule name
     */
    rule_name: string;
    /**
     * Field→value map that must match for rule to fire
     */
    conditions?: Record<string, any>;
    /**
     * escalate | investigate | monitor | close | block
     */
    action?: string;
    /**
     * Override severity when rule fires
     */
    override_severity?: string;
    /**
     * Optional tag
     */
    tag?: string;
    enabled?: boolean;
};

