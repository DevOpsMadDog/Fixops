/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EscalationLevel } from './EscalationLevel';
import type { SLAStatusV2 } from './SLAStatusV2';
/**
 * SLA assignment record for a finding.
 */
export type SLAAssignment = {
    id?: string;
    finding_id: string;
    org_id: string;
    team_id?: (string | null);
    asset_tier?: string;
    severity: string;
    frameworks?: Array<string>;
    discovered_at: string;
    deadline: string;
    business_hours?: boolean;
    status?: SLAStatusV2;
    pct_elapsed?: number;
    escalation_level?: EscalationLevel;
    breached_at?: (string | null);
    resolved_at?: (string | null);
    created_at?: string;
};

