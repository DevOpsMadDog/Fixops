/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for targeted spike / drop detection.
 */
export type SpikeDropRequest = {
    /**
     * Metric to analyse
     */
    metric_name: string;
    /**
     * Percentage deviation that triggers the anomaly
     */
    threshold_pct: number;
    /**
     * Organisation ID
     */
    org_id?: string;
};

