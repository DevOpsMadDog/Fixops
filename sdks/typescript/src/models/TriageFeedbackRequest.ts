/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Analyst feedback on a triaged finding.
 */
export type TriageFeedbackRequest = {
    finding_id: string;
    /**
     * accept, reject, escalate, or false_positive
     */
    analyst_verdict: string;
    reason?: (string | null);
    analyst_id?: (string | null);
};

