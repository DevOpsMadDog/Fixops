/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for advancing an incident to the next phase.
 */
export type AdvancePhaseRequest = {
    /**
     * Approver username (required for gated phases)
     */
    approved_by?: (string | null);
    /**
     * Phase completion notes
     */
    notes?: string;
};

