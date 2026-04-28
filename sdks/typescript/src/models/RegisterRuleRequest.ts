/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterRuleRequest = {
    rule_key: string;
    conditions?: Record<string, any>;
    max_active_count?: number;
    approvers?: Array<string>;
    expires_days?: number;
};

