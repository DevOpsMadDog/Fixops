/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssessmentResultItem = {
    /**
     * Control identifier
     */
    control_id: string;
    /**
     * Control name
     */
    control_name?: string;
    /**
     * pass | fail | skip
     */
    status: string;
    /**
     * Observed configuration value
     */
    actual_value?: string;
    /**
     * Description of deviation from expected
     */
    deviation?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
};

