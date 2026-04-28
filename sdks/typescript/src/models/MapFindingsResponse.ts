/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingMappingResponse } from './FindingMappingResponse';
import type { KillChainCoverageResponse } from './KillChainCoverageResponse';
export type MapFindingsResponse = {
    session_id: string;
    mapped_at: string;
    total_findings: number;
    total_techniques: number;
    total_tactics_covered: number;
    coverage_percentage: number;
    all_techniques: Array<string>;
    technique_frequency: Record<string, number>;
    kill_chain_coverage: Array<KillChainCoverageResponse>;
    finding_results: Array<FindingMappingResponse>;
};

