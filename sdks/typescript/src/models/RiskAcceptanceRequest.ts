/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReviewPriority } from './ReviewPriority';
/**
 * Payload for requesting a new risk acceptance.
 */
export type RiskAcceptanceRequest = {
    finding_id: string;
    justification: string;
    business_reason: string;
    compensating_controls?: string;
    requested_by: string;
    expires_at: string;
    priority?: ReviewPriority;
    conditions?: Array<string>;
    risk_score_at_acceptance?: number;
};

