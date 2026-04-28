/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for recording a metric data point.
 */
export type apps__api__anomaly_router__RecordMetricRequest = {
    /**
     * Metric name, e.g. 'cpu_usage'
     */
    name: string;
    /**
     * Numeric metric value
     */
    value: number;
    /**
     * Organisation ID
     */
    org_id?: string;
};

