/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FAIRResultResponse } from './FAIRResultResponse';
/**
 * Aggregated FAIR portfolio risk summary.
 */
export type FAIRRiskSummaryResponse = {
    scenarios: Array<FAIRResultResponse>;
    total_ale_p10_usd: number;
    total_ale_p50_usd: number;
    total_ale_p90_usd: number;
    total_ale_mean_usd: number;
    computed_at: string;
};

