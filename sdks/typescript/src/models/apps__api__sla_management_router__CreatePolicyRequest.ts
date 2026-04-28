/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EscalationRule } from './EscalationRule';
/**
 * Request to create or update a scoped SLA policy.
 */
export type apps__api__sla_management_router__CreatePolicyRequest = {
    /**
     * Human-readable policy name
     */
    name: string;
    /**
     * Scope to a specific team
     */
    team_id?: (string | null);
    /**
     * Scope to asset tier: tier1–tier5
     */
    asset_tier?: (string | null);
    /**
     * SLA deadline in hours per severity level
     */
    severity_deadlines?: Record<string, number>;
    /**
     * Per-framework deadline overrides (pci-dss, hipaa, soc2, etc.)
     */
    framework_overrides?: Record<string, Record<string, number>>;
    /**
     * Count only business hours (Mon–Fri 09:00–17:00) against SLA
     */
    business_hours_only?: boolean;
    /**
     * Timezone for business hours calculation
     */
    tz_name?: string;
    /**
     * Escalation contacts per severity
     */
    escalation_rules?: Array<EscalationRule>;
    enabled?: boolean;
};

