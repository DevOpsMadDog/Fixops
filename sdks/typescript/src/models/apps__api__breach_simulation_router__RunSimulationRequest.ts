/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AttackScenario } from './AttackScenario';
/**
 * Request to run a breach simulation.
 */
export type apps__api__breach_simulation_router__RunSimulationRequest = {
    /**
     * Attack scenario to simulate
     */
    scenario: AttackScenario;
    /**
     * Organisation identifier
     */
    org_id: string;
};

