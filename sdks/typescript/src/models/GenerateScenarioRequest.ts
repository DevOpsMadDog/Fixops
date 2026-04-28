/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to AI-generate a scenario.
 */
export type GenerateScenarioRequest = {
    /**
     * Description of the target
     */
    target_description?: string;
    /**
     * Alias for target_description
     */
    target?: (string | null);
    /**
     * Threat actor profile
     */
    threat_actor?: string;
    /**
     * Type of attack (e.g., rce, xss)
     */
    attack_type?: (string | null);
    /**
     * Known CVEs
     */
    cve_ids?: Array<string>;
};

