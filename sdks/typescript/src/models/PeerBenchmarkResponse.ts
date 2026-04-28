/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BenchmarkMetricResponse } from './BenchmarkMetricResponse';
/**
 * Peer benchmarking result.
 */
export type PeerBenchmarkResponse = {
    vertical: string;
    org_id: string;
    metrics: Array<BenchmarkMetricResponse>;
    overall_percentile: number;
    computed_at: string;
};

