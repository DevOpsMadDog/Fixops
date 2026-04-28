/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Submit analyst feedback on a finding.
 */
export type api__brain_router__FPFeedbackRequest = {
    /**
     * Finding ID to provide feedback on
     */
    finding_id: string;
    /**
     * True if this is a false positive
     */
    is_false_positive: boolean;
    /**
     * Reason for the classification
     */
    reason?: string;
    /**
     * Scanner that produced the finding
     */
    scanner?: string;
    /**
     * CWE ID of the finding
     */
    cwe_id?: string;
    /**
     * Application ID
     */
    app_id?: string;
    /**
     * Organization ID
     */
    org_id?: string;
    /**
     * Rule/check ID that fired
     */
    rule_id?: string;
    /**
     * Finding title
     */
    title?: string;
    /**
     * Analyst who reviewed
     */
    analyst?: string;
};

