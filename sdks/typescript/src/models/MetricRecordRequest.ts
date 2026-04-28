/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to record a custom metric.
 */
export type MetricRecordRequest = {
    /**
     * Metric name
     */
    metric_name: string;
    /**
     * Metric value
     */
    value: number;
    /**
     * Unit of measurement
     */
    unit?: string;
    /**
     * Metric type
     */
    metric_type?: string;
    /**
     * Dimensional breakdown
     */
    dimensions?: (Record<string, any> | null);
    /**
     * Data point timestamp
     */
    timestamp?: (string | null);
};

