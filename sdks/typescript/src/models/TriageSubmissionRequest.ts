/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__bug_bounty__Severity } from './core__bug_bounty__Severity';
import type { SubmissionStatus } from './SubmissionStatus';
export type TriageSubmissionRequest = {
    /**
     * Triage decision: triaging | accepted | rejected | duplicate | informational
     */
    decision: SubmissionStatus;
    /**
     * Assigned severity
     */
    severity?: (core__bug_bounty__Severity | null);
    /**
     * CVSS v3 score
     */
    cvss_score?: (number | null);
    /**
     * Internal triage notes
     */
    notes?: string;
};

