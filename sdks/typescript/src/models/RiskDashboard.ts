/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AttackSignal } from './AttackSignal';
import type { DependencyRiskScore } from './DependencyRiskScore';
/**
 * Aggregated supply chain risk dashboard data.
 */
export type RiskDashboard = {
    org_id: string;
    total_components: number;
    total_sboms: number;
    critical_components: number;
    high_risk_components: number;
    attack_signals: number;
    critical_attack_signals: number;
    policy_violations: number;
    blocked_components: number;
    avg_risk_score: number;
    top_risks: Array<DependencyRiskScore>;
    recent_signals: Array<AttackSignal>;
    vendor_count: number;
    high_risk_vendors: number;
    computed_at?: string;
};

