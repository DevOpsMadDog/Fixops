/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BenchmarkMetric } from './BenchmarkMetric';
import type { IndustryVertical_Output } from './IndustryVertical_Output';
/**
 * Full benchmark report for an organisation at a point in time.
 */
export type BenchmarkReport = {
    id?: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Industry vertical used for comparison
     */
    vertical: IndustryVertical_Output;
    metrics?: Array<BenchmarkMetric>;
    /**
     * Weighted average percentile rank across all metrics
     */
    overall_percentile: number;
    /**
     * Metrics where org outperforms the industry average
     */
    strengths?: Array<string>;
    /**
     * Metrics where org underperforms the industry average
     */
    weaknesses?: Array<string>;
    /**
     * Prioritised improvement recommendations
     */
    recommendations?: Array<string>;
    /**
     * ISO-8601 UTC timestamp
     */
    generated_at?: string;
};

