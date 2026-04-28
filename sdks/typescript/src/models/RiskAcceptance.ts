/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AcceptanceStatus } from './AcceptanceStatus';
import type { ReviewPriority } from './ReviewPriority';
/**
 * A formal risk acceptance record.
 */
export type RiskAcceptance = {
    id?: string;
    finding_id: string;
    org_id: string;
    justification: string;
    business_reason: string;
    compensating_controls?: string;
    requested_by: string;
    requested_at?: string;
    approved_by?: (string | null);
    approved_at?: (string | null);
    expires_at: string;
    review_date: string;
    status?: AcceptanceStatus;
    priority?: ReviewPriority;
    conditions?: Array<string>;
    risk_score_at_acceptance?: number;
};

