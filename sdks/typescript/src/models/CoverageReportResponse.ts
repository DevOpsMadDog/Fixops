/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CoreCoverageResponse } from './CoreCoverageResponse';
/**
 * Overall coverage report across all Knowledge Cores.
 */
export type CoverageReportResponse = {
    cores: Record<string, CoreCoverageResponse>;
    total_coverage_pct: number;
    total_entities: number;
    connected_entities: number;
    orphaned_count: number;
    last_checked: string;
};

