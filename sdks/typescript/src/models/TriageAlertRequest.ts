/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TriageAlertRequest = {
    /**
     * new | triaging | escalated | investigating | resolved | false_positive | duplicate
     */
    triage_status: string;
    /**
     * Assignee username
     */
    assigned_to?: (string | null);
    /**
     * Analyst notes
     */
    triage_notes?: (string | null);
    /**
     * Required when escalating
     */
    escalation_reason?: (string | null);
};

