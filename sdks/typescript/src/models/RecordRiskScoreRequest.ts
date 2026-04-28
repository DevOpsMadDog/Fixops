/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordRiskScoreRequest = {
    /**
     * Unique identifier for the entity
     */
    entity_id: string;
    /**
     * Human-readable entity name
     */
    entity_name?: (string | null);
    /**
     * asset | user | network | application | vendor
     */
    entity_type?: string;
    /**
     * Engine producing the score
     */
    source_engine?: (string | null);
    /**
     * Risk score 0-100
     */
    risk_score: number;
    /**
     * Contributing risk factors
     */
    risk_factors?: (Array<string> | null);
    /**
     * Override severity: critical | high | medium | low (auto-derived if omitted)
     */
    severity?: (string | null);
};

