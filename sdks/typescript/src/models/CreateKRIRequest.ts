/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateKRIRequest = {
    /**
     * ID of the associated risk
     */
    risk_id: string;
    /**
     * KRI name
     */
    name: string;
    description?: string;
    /**
     * Measurement unit, e.g. 'count', '%'
     */
    unit?: string;
    /**
     * Current measured value
     */
    current_value?: number;
    /**
     * Warning level threshold
     */
    warning_threshold: number;
    /**
     * Breach level threshold
     */
    breach_threshold: number;
    /**
     * higher_is_worse | lower_is_worse
     */
    direction?: string;
    org_id?: string;
};

