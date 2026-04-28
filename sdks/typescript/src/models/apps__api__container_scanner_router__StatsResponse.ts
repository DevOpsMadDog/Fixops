/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__container_scanner_router__StatsResponse = {
    total_scans: number;
    avg_score: number;
    total_findings: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
};

