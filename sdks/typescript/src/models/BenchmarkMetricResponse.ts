/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Single benchmark metric comparison.
 */
export type BenchmarkMetricResponse = {
    metric_name: string;
    org_value: number;
    industry_p25: number;
    industry_p50: number;
    industry_p75: number;
    unit: string;
    percentile_rank: number;
    is_lower_better: boolean;
};

