/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__self_learning_router__FPFeedbackRequest = {
    /**
     * Finding ID
     */
    finding_id: string;
    /**
     * Scanner name
     */
    scanner: string;
    /**
     * Rule/check ID
     */
    rule_id: string;
    /**
     * Analyst marked as FP?
     */
    is_false_positive: boolean;
    context?: Record<string, any>;
};

