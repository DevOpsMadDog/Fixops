/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SetBenchmarkRequest = {
    /**
     * Metric type to benchmark
     */
    metric_type: string;
    /**
     * Organisation target value
     */
    target_value: number;
    /**
     * Industry average value
     */
    industry_average: number;
    /**
     * Benchmark period
     */
    period?: string;
};

