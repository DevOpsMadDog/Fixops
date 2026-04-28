/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Top-level KPI response.
 */
export type KPIResponse = {
    /**
     * Mean Time To Detect
     */
    mttd_minutes: number;
    /**
     * Mean Time To Remediate
     */
    mttr_hours: number;
    /**
     * False Positive Rate
     */
    false_positive_rate_percent: number;
    /**
     * Critical findings
     */
    findings_critical: number;
    /**
     * High findings
     */
    findings_high: number;
    /**
     * Connector uptime
     */
    connector_uptime_percent: number;
    /**
     * LLM council consensus
     */
    council_consensus_percent: number;
    /**
     * SLA compliance
     */
    sla_compliance_percent: number;
};

