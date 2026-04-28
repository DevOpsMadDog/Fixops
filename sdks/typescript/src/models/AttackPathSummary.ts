/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Summarized attack path information for a finding.
 */
export type AttackPathSummary = {
    path_count?: number;
    max_depth?: number;
    internet_reachable?: boolean;
    highest_score?: number;
    paths?: Array<Record<string, any>>;
};

