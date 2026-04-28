/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_awareness_metrics_router__RecordMetricRequest = {
    /**
     * phishing_click_rate | training_completion | quiz_score | policy_acknowledgement | incident_report_rate | password_strength
     */
    metric_type: string;
    /**
     * Department name or 'all'
     */
    department?: string;
    /**
     * Metric value (percentage, score, etc.)
     */
    value: number;
    /**
     * Period label e.g. '2024-Q1'
     */
    period?: string;
    /**
     * Number of people sampled
     */
    sample_size?: number;
};

