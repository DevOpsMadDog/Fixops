/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_monitoring_router__AlertRuleRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Target interface ID
     */
    interface_id: string;
    /**
     * Metric to monitor
     */
    metric?: string;
    /**
     * Alert threshold value
     */
    threshold?: number;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
};

