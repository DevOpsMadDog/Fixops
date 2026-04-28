/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__posture_benchmark__IndustryVertical } from './core__posture_benchmark__IndustryVertical';
export type GenerateBenchmarkRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Industry vertical for comparison
     */
    vertical: core__posture_benchmark__IndustryVertical;
    /**
     * Metric name -> measured value (optional; previously stored values used if omitted)
     */
    org_metrics?: (Record<string, number> | null);
};

