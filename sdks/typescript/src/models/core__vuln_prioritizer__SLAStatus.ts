/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * SLA compliance dashboard per team.
 */
export type core__vuln_prioritizer__SLAStatus = {
    org_id: string;
    team?: (string | null);
    total_open: number;
    within_sla: number;
    breached: number;
    breach_rate: number;
    by_bucket?: Record<string, number>;
    breached_by_bucket?: Record<string, number>;
    as_of?: string;
};

