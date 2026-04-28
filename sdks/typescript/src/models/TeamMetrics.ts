/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TrendDirection } from './TrendDirection';
/**
 * Per-team SLA performance metrics for a reporting period.
 */
export type TeamMetrics = {
    id?: string;
    org_id: string;
    team_id: string;
    period_start: string;
    period_end: string;
    total_assigned?: number;
    resolved_within?: number;
    breached?: number;
    avg_resolution_hours?: number;
    compliance_rate?: number;
    trend?: TrendDirection;
    computed_at?: string;
};

