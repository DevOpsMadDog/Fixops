/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after recording analyst feedback.
 */
export type TriageFeedbackResponse = {
    feedback_id: string;
    finding_id: string;
    verdict: string;
    recorded_at: string;
    confidence_updated?: boolean;
    updated_confidence?: (number | null);
};

