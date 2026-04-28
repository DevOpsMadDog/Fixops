/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Analyst feedback on a finding's priority.
 */
export type apps__api__prioritizer_router__FeedbackRequest = {
    /**
     * Finding ID
     */
    finding_id: string;
    /**
     * Analyst judgement: critical_now | act_soon | monitor | defer
     */
    analyst_priority: string;
};

