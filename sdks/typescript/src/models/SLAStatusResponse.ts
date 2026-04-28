/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * SLA status response for a single finding.
 */
export type SLAStatusResponse = {
    finding_id: string;
    status: string;
    severity: string;
    asset_tier: string;
    deadline: string;
    discovered_at: string;
    pct_elapsed: number;
    escalation_level: string;
    breached_at: (string | null);
    resolved_at: (string | null);
    frameworks: Array<string>;
    business_hours: boolean;
};

