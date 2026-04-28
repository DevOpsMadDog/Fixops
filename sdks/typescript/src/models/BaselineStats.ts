/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Statistical baseline for a metric.
 */
export type BaselineStats = {
    metric_name: string;
    org_id: string;
    mean: number;
    std_dev: number;
    min_value: number;
    max_value: number;
    sample_count: number;
    window_days: number;
    computed_at?: string;
};

