/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single review action against a RiskAcceptance.
 */
export type AcceptanceReview = {
    id?: string;
    acceptance_id: string;
    reviewer: string;
    decision: string;
    comment?: string;
    reviewed_at?: string;
};

