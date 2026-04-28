/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriageFindingInput } from './TriageFindingInput';
/**
 * Request body for /enrich — single finding or batch.
 */
export type TriageEnrichRequest = {
    /**
     * One or more findings to enrich
     */
    findings: Array<TriageFindingInput>;
};

