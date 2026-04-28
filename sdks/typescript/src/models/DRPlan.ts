/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DRPlanStatus } from './DRPlanStatus';
import type { RunbookStep } from './RunbookStep';
/**
 * Disaster Recovery plan with runbook steps and communication plan.
 */
export type DRPlan = {
    id?: string;
    name: string;
    system_name: string;
    status?: DRPlanStatus;
    /**
     * Lower = higher priority for recovery
     */
    priority_order?: number;
    runbook_steps?: Array<RunbookStep>;
    responsible_parties?: Array<string>;
    /**
     * Who to notify, escalation path, channels, templates
     */
    communication_plan?: Record<string, any>;
    rto_minutes?: number;
    rpo_minutes?: number;
    version?: string;
    approved_by?: (string | null);
    approved_at?: (string | null);
    last_reviewed_at?: (string | null);
    next_review_at?: (string | null);
    tags?: Array<string>;
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

