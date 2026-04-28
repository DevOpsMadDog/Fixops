/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AlertRuleCreate = {
    /**
     * Alert rule name
     */
    name: string;
    /**
     * Telemetry type to monitor
     */
    telemetry_type: string;
    /**
     * avg/sum/max/min/count/p95/p99
     */
    aggregation?: string;
    /**
     * Threshold value
     */
    threshold?: number;
    /**
     * gt/lt/gte/lte
     */
    operator?: string;
    /**
     * Optional source filter
     */
    source?: string;
};

