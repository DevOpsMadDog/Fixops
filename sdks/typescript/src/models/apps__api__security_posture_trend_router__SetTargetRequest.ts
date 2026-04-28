/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_posture_trend_router__SetTargetRequest = {
    /**
     * Metric to target
     */
    metric_name: string;
    /**
     * Desired target value
     */
    target_value: number;
    /**
     * Current metric value
     */
    current_value: number;
    /**
     * Who set the target
     */
    set_by?: string;
};

