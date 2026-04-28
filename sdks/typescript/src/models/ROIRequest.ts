/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for ROI calculation.
 */
export type ROIRequest = {
    /**
     * Total annual program cost in USD
     */
    program_cost_usd: number;
    /**
     * Estimated breaches prevented
     */
    breaches_prevented: number;
    tool_cost_usd?: number;
    staff_cost_usd?: number;
    training_cost_usd?: number;
    /**
     * Industry vertical for breach cost lookup
     */
    industry?: string;
};

