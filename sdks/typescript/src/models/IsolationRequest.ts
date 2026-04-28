/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IsolationRequest = {
    /**
     * Entity to score
     */
    entity_id: string;
    /**
     * Feature metric names
     */
    metric_names: Array<string>;
    /**
     * Current feature vector
     */
    current_values: Array<number>;
    /**
     * Training window in days
     */
    window_days?: number;
    /**
     * Organisation ID
     */
    org_id?: string;
};

