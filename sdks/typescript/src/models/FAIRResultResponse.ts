/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * FAIR simulation output.
 */
export type FAIRResultResponse = {
    scenario_name: string;
    ale_p10_usd: number;
    ale_p50_usd: number;
    ale_p90_usd: number;
    ale_mean_usd: number;
    max_single_loss_usd: number;
    loss_exceedance_probability: number;
    simulation_iterations: number;
    computed_at: string;
};

