/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KillChainCoverageResponse } from './KillChainCoverageResponse';
export type api__mitre_mapper_router__KillChainResponse = {
    session_id: string;
    mapped_at: string;
    total_findings: number;
    total_tactics_covered: number;
    total_tactics: number;
    coverage_percentage: number;
    kill_chain_coverage: Array<KillChainCoverageResponse>;
    summary: Record<string, any>;
};

