/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__privilege_escalation_router__CreateRuleRequest = {
    /**
     * Organization identifier
     */
    org_id: string;
    /**
     * Rule name
     */
    name: string;
    /**
     * Regex pattern to match against event strings
     */
    pattern: string;
    /**
     * critical/high/medium/low
     */
    severity?: string;
    /**
     * alert/block/log
     */
    action?: string;
};

