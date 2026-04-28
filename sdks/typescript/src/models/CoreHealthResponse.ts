/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Health score for a single Knowledge Core.
 */
export type CoreHealthResponse = {
    core_id: number;
    core_name: string;
    score: number;
    total_entities: number;
    connected_pct: number;
    stale_pct: number;
    missing_severity_count: number;
    reason: string;
};

