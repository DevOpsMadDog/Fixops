/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Lightweight posture record at a point in time.
 */
export type PostureSnapshot = {
    /**
     * Unique snapshot identifier
     */
    snapshot_id?: string;
    /**
     * ISO-8601 UTC timestamp
     */
    timestamp?: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Posture score 0-100
     */
    overall_score: number;
    /**
     * Open critical severity findings
     */
    critical_findings?: number;
    /**
     * Open high severity findings
     */
    high_findings?: number;
    /**
     * Open medium severity findings
     */
    medium_findings?: number;
    /**
     * Open low severity findings
     */
    low_findings?: number;
    /**
     * Percentage of findings resolved within SLA
     */
    sla_compliance_rate?: number;
    /**
     * Percentage of assets indexed in TrustGraph
     */
    trustgraph_coverage?: number;
    /**
     * Findings remediated in last 30 days (%)
     */
    remediation_rate?: number;
    /**
     * Trend vs previous snapshot: 'improving', 'stable', or 'degrading'
     */
    trend?: string;
    /**
     * Raw component scores from PostureScorer (optional)
     */
    components?: Record<string, any>;
};

