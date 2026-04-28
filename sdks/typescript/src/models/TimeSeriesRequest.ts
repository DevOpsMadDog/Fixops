/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TimeSeriesRequest = {
    /**
     * User or service ID
     */
    entity_id: string;
    /**
     * Metric to analyse
     */
    metric_name: string;
    /**
     * Analysis window in hours
     */
    window_hours?: number;
    /**
     * Entity type
     */
    entity_type?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

