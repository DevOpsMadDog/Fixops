/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DecisionFeedbackRequest = {
    /**
     * AI decision ID
     */
    decision_id: string;
    /**
     * Finding ID
     */
    finding_id: string;
    /**
     * What AI decided
     */
    predicted_action: string;
    /**
     * What actually happened
     */
    actual_outcome: string;
    confidence?: number;
    context?: Record<string, any>;
};

