/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for metrics.
 */
export type MetricResponse = {
    metric_id: string;
    name: string;
    metric_type: string;
    value: number;
    unit: string;
    timestamp: string;
    dimensions?: Record<string, any>;
    trend_direction?: string;
    trend_percent?: number;
};

