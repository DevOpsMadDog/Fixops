/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EscalationRule } from './EscalationRule';
/**
 * Extended SLA policy with business hours and framework support.
 */
export type SLAPolicyV2 = {
    id?: string;
    org_id: string;
    team_id?: (string | null);
    asset_tier?: (string | null);
    name: string;
    severity_deadlines?: Record<string, number>;
    framework_overrides?: Record<string, Record<string, number>>;
    business_hours_only?: boolean;
    tz_name?: string;
    escalation_rules?: Array<EscalationRule>;
    enabled?: boolean;
    created_at?: string;
    updated_at?: string;
};

