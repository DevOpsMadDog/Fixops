/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AttackPathSummary } from './AttackPathSummary';
import type { ComplianceImpact } from './ComplianceImpact';
/**
 * Enriched finding returned from /enrich.
 */
export type TriageEnrichedFinding = {
    finding: Record<string, any>;
    attack_paths: AttackPathSummary;
    compliance_impact: ComplianceImpact;
    sla_deadline: string;
    sla_hours_remaining: number;
    confidence_adjustment?: (number | null);
    recommended_action: string;
    enrichment_sources?: Array<string>;
};

