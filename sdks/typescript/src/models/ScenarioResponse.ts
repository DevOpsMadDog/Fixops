/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Scenario response.
 */
export type ScenarioResponse = {
    scenario_id: string;
    name: string;
    description: string;
    threat_actor: string;
    complexity: string;
    target_assets: Array<string>;
    target_cves: Array<string>;
    kill_chain_phases: Array<string>;
    objectives: Array<string>;
    created_at: string;
};

