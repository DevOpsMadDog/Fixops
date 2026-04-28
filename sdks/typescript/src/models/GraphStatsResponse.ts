/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * High-level graph statistics.
 */
export type GraphStatsResponse = {
    total_entities: number;
    total_relationships: number;
    entities_per_core: Record<string, number>;
    relationships_per_core: Record<string, number>;
    coverage_pct: number;
    orphaned_count: number;
    last_updated: (string | null);
    db_path: string;
};

