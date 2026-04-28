/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for attack path simulation.
 */
export type SimulationRequest = {
    /**
     * Starting security state
     */
    start_state?: string;
    /**
     * Maximum simulation steps
     */
    max_steps?: number;
    /**
     * Random seed for reproducibility
     */
    seed?: (number | null);
};

