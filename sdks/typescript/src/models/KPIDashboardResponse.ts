/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KPIMetricResponse } from './KPIMetricResponse';
/**
 * KPI dashboard response.
 */
export type KPIDashboardResponse = {
    org_id: string;
    kpis: Array<KPIMetricResponse>;
    overall_health_score: number;
    on_track_count: number;
    at_risk_count: number;
    breached_count: number;
    computed_at: string;
};

