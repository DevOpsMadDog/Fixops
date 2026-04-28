/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateMitigationRuleRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Rule name
     */
    name: string;
    /**
     * rate_limit | geo_block | ip_block | challenge
     */
    rule_type: string;
    /**
     * Rule threshold value
     */
    threshold: any;
    /**
     * Action to take when rule triggers
     */
    action: string;
};

