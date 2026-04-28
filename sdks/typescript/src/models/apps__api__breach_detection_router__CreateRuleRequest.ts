/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__breach_detection_router__CreateRuleRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Rule name
     */
    name: string;
    /**
     * behavioral/signature/anomaly/heuristic/ml_based
     */
    rule_type: string;
    /**
     * endpoint/network/cloud/email/identity/application
     */
    data_source?: string;
    /**
     * Alert threshold count
     */
    threshold?: number;
    /**
     * Rule status
     */
    status?: string;
};

