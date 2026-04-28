/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MetricsResponse = {
    total_created: number;
    total_open: number;
    total_closed: number;
    avg_time_to_close_hours: number;
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
    by_state: Record<string, number>;
};

