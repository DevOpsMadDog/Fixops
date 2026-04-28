/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create an attack scenario.
 */
export type api__attack_sim_router__CreateScenarioRequest = {
    /**
     * Scenario name
     */
    name: string;
    /**
     * Scenario description
     */
    description?: string;
    /**
     * Threat actor profile
     */
    threat_actor?: string;
    /**
     * Attack complexity
     */
    complexity?: string;
    /**
     * Target assets
     */
    target_assets?: Array<string>;
    /**
     * CVEs to exploit
     */
    target_cves?: Array<string>;
    /**
     * Attack objectives
     */
    objectives?: Array<string>;
    /**
     * MITRE technique ID for initial access
     */
    initial_access_vector?: string;
};

