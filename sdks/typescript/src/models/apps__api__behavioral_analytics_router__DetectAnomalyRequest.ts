/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__behavioral_analytics_router__DetectAnomalyRequest = {
    org_id?: string;
    user_id: string;
    behavior_type?: string;
    severity?: string;
    observed_value?: number;
    baseline_value?: number;
    deviation_score?: number;
    description?: string;
    detected_at?: (string | null);
};

