/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddMetricRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Metric name
     */
    metric_name: string;
    /**
     * Current metric value
     */
    metric_value: number;
    /**
     * Unit label (e.g. %, ms, count)
     */
    metric_unit?: string;
    /**
     * Previous period value for trend computation
     */
    previous_value?: number;
    /**
     * Industry benchmark value
     */
    benchmark_value?: number;
};

