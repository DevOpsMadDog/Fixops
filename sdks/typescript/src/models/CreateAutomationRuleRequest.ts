/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAutomationRuleRequest = {
    /**
     * Human-readable rule name
     */
    rule_name: string;
    /**
     * Trigger condition expression
     */
    trigger_condition?: string;
    /**
     * auto_close | escalate | enrich | notify | block | isolate
     */
    action_type?: string;
    confidence_threshold?: number;
    enabled?: boolean;
};

