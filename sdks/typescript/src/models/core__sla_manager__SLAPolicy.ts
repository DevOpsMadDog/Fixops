/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Per-org SLA policy with severity-specific deadlines.
 */
export type core__sla_manager__SLAPolicy = {
    id?: string;
    org_id: string;
    name: string;
    severity_deadlines?: Record<string, number>;
    escalation_chain?: Array<string>;
    grace_period_hours?: number;
    enabled?: boolean;
};

