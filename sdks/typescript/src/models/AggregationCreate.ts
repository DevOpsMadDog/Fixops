/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AggregationCreate = {
    aggregation_name: string;
    metric_names?: Array<string>;
    aggregation_type?: string;
    time_window_hours?: number;
    result_value?: number;
    confidence?: number;
    computed_at?: (string | null);
};

