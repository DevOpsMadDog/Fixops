/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_telemetry_router__AggregateRequest = {
    /**
     * Type of telemetry metric
     */
    telemetry_type: string;
    /**
     * avg/sum/max/min/count/p95/p99
     */
    aggregation?: string;
    /**
     * Filter by source
     */
    source?: (string | null);
    /**
     * Look-back window in hours
     */
    hours?: number;
};

