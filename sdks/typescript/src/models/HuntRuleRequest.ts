/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type HuntRuleRequest = {
    name: string;
    description?: string;
    query: string;
    /**
     * low/medium/high/critical
     */
    severity?: string;
    auto_alert?: boolean;
};

