/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KPIHealth } from './KPIHealth';
import type { KPIHealthStatus } from './KPIHealthStatus';
/**
 * CISO-facing executive summary of top KPIs.
 */
export type ExecutiveKPISummary = {
    org_id: string;
    generated_at: string;
    overall_health: KPIHealth;
    kpis: Array<KPIHealthStatus>;
    green_count: number;
    yellow_count: number;
    red_count: number;
    unknown_count: number;
};

