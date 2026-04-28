/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MetricDefinitionCreate = {
    name: string;
    description?: string;
    category?: string;
    unit?: string;
    target_value?: (number | null);
    critical_threshold?: (number | null);
    warning_threshold?: (number | null);
    enabled?: number;
};

