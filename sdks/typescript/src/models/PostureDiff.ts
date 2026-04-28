/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Comparison between two PostureSnapshots.
 */
export type PostureDiff = {
    snapshot_id_1: string;
    snapshot_id_2: string;
    timestamp_1: string;
    timestamp_2: string;
    org_id: string;
    /**
     * score2 - score1 (positive = improved)
     */
    score_delta: number;
    /**
     * critical_findings2 - critical_findings1
     */
    critical_delta: number;
    /**
     * high_findings2 - high_findings1
     */
    high_delta: number;
    /**
     * sla_compliance_rate2 - sla_compliance_rate1
     */
    sla_delta: number;
    /**
     * trustgraph_coverage2 - trustgraph_coverage1
     */
    coverage_delta: number;
    /**
     * remediation_rate2 - remediation_rate1
     */
    remediation_delta: number;
    /**
     * 'improving', 'stable', or 'degrading'
     */
    trend: string;
    /**
     * Human-readable summary of changes
     */
    summary: string;
};

