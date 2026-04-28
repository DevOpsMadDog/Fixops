/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Coverage stats for one Knowledge Core.
 */
export type CoreCoverageResponse = {
    core_id: number;
    core_name: string;
    total_entities: number;
    connected_entities: number;
    orphaned_entities: number;
    coverage_pct: number;
    entity_type_breakdown: Record<string, number>;
    last_updated: (string | null);
};

