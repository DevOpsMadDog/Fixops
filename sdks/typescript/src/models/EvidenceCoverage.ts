/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Coverage report: which controls have fresh evidence.
 */
export type EvidenceCoverage = {
    org_id: string;
    framework: string;
    total_controls: number;
    covered_controls: number;
    coverage_pct: number;
    fresh_controls: Array<string>;
    stale_controls: Array<string>;
    missing_controls: Array<string>;
    generated_at?: string;
};

