/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Input model for creating an alert rule.
 */
export type apps__api__observability_router__AlertRuleRequest = {
    name: string;
    metric_key: string;
    /**
     * gt | lt | gte | lte | eq
     */
    condition: string;
    threshold: number;
    action?: string;
    cooldown_seconds?: number;
    severity?: string;
};

