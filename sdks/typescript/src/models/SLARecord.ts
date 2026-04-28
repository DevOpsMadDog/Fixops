/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__sla_manager__SLAStatus } from './core__sla_manager__SLAStatus';
/**
 * Tracks SLA compliance for a single finding.
 */
export type SLARecord = {
    id?: string;
    finding_id: string;
    org_id: string;
    severity: string;
    discovered_at: string;
    deadline: string;
    status?: core__sla_manager__SLAStatus;
    breached_at?: (string | null);
    resolved_at?: (string | null);
    escalated?: boolean;
    exempt_reason?: (string | null);
};

