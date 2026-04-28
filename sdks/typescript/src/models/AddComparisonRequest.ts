/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddComparisonRequest = {
    org_id?: string;
    /**
     * Benchmark to compare
     */
    benchmark_id: string;
    /**
     * Peer group: enterprise, smb, startup, government, healthcare, finance, retail
     */
    peer_group: string;
    peer_avg_score?: number;
    our_score?: number;
    percentile_rank?: number;
};

