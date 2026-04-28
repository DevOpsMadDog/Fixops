/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DecisionOutcome } from './DecisionOutcome';
/**
 * Request model for creating a decision.
 */
export type apps__api__analytics_router__DecisionCreate = {
    finding_id: string;
    outcome: DecisionOutcome;
    confidence: number;
    reasoning: string;
    llm_votes?: Record<string, any>;
    policy_matched?: (string | null);
};

