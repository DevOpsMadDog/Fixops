/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ZScoreRequest = {
    /**
     * User or service ID
     */
    entity_id: string;
    /**
     * Metric to evaluate
     */
    metric_name: string;
    /**
     * Observed value to test
     */
    value: number;
    /**
     * Baseline window in days
     */
    window_days?: number;
    /**
     * Sigma threshold
     */
    z_threshold?: number;
    /**
     * Entity type
     */
    entity_type?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

