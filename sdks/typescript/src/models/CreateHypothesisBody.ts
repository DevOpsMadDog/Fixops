/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateHypothesisBody = {
    /**
     * Hypothesis statement
     */
    hypothesis: string;
    /**
     * lateral_movement | privilege_escalation | exfiltration | persistence | defense_evasion | discovery | collection | impact
     */
    threat_category?: string;
    /**
     * MITRE ATT&CK technique ID e.g. T1078
     */
    mitre_technique?: string;
    /**
     * low | medium | high
     */
    confidence?: string;
    /**
     * List of data sources
     */
    data_sources?: Array<string>;
    /**
     * Creator user ID
     */
    created_by?: string;
};

