/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Single weekly risk posture snapshot.
 */
export type TrendSnapshotResponse = {
    week_start: string;
    total_risk_score: number;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
    low_vulns: number;
    compliance_pct: number;
    mttr_days: number;
    new_findings: number;
    resolved_findings: number;
    new_vs_resolved_ratio: number;
};

