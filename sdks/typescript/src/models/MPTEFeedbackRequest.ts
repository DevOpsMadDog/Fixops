/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MPTEFeedbackRequest = {
    /**
     * Finding ID
     */
    finding_id: string;
    /**
     * Was it predicted exploitable?
     */
    predicted_exploitable: boolean;
    /**
     * Was it actually exploitable?
     */
    actual_exploitable: boolean;
    mpte_confidence?: number;
    context?: Record<string, any>;
};

