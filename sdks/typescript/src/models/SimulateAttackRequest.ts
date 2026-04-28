/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to simulate attack scenario.
 */
export type SimulateAttackRequest = {
    /**
     * ransomware, apt, insider
     */
    scenario_type?: string;
    target_assets: Array<string>;
    kill_chain_stages?: Array<string>;
};

