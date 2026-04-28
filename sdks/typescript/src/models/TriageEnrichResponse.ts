/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriageEnrichedFinding } from './TriageEnrichedFinding';
/**
 * Response for /enrich.
 */
export type TriageEnrichResponse = {
    enriched: Array<TriageEnrichedFinding>;
    total: number;
    enrichment_available: Record<string, boolean>;
    timestamp: string;
};

