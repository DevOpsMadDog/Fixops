/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single point in a vulnerability trend time-series.
 */
export type TrendPoint = {
    /**
     * ISO date string for the bucket (YYYY-MM-DD)
     */
    date: string;
    /**
     * Findings opened during the period
     */
    new_count?: number;
    /**
     * Findings resolved during the period
     */
    resolved_count?: number;
    /**
     * Findings reopened during the period
     */
    reopened_count?: number;
    /**
     * Total open findings at end of period
     */
    total_open?: number;
};

