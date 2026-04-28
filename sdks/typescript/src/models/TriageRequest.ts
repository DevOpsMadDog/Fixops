/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to mark a drill finding as triaged.
 */
export type TriageRequest = {
    /**
     * Triage classification. One of: real_critical, real_high, real_medium, real_low, false_positive, synthetic, wont_fix
     */
    classification: string;
    /**
     * Who performed triage
     */
    triaged_by?: (string | null);
    /**
     * Was the finding escalated?
     */
    escalated?: boolean;
    /**
     * Teams notified during triage
     */
    notified_teams?: Array<string>;
    /**
     * Notes from triage
     */
    triage_note?: string;
};

