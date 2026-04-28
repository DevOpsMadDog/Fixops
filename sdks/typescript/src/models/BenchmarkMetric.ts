/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single metric with org value vs. industry benchmarks.
 */
export type BenchmarkMetric = {
    /**
     * Metric identifier (e.g. 'mttr_days')
     */
    name: string;
    /**
     * Organisation's measured value
     */
    org_value: number;
    /**
     * Industry average for this vertical
     */
    industry_avg: number;
    /**
     * Industry 90th-percentile (top performers) for this vertical
     */
    industry_p90: number;
    /**
     * Org's percentile rank vs. industry (higher = better)
     */
    percentile_rank: number;
    /**
     * Difference between org value and industry average (positive = org is better)
     */
    gap: number;
};

