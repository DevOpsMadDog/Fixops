/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * API response for a simulation result.
 */
export type SimulationResultResponse = {
    id: string;
    scenario: string;
    steps_executed: number;
    steps_blocked: number;
    detection_time_seconds: number;
    containment_time_seconds: number;
    data_at_risk: string;
    defenses_tested: Array<string>;
    gaps_found: Array<string>;
    score: number;
    org_id: string;
    simulated_at: string;
};

