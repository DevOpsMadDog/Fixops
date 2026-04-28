/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a decision.
 */
export type apps__api__analytics_router__DecisionResponse = {
    id: string;
    finding_id: string;
    outcome: string;
    confidence: number;
    reasoning: string;
    llm_votes: Record<string, any>;
    policy_matched: (string | null);
    created_at: string;
};

