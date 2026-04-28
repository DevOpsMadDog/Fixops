/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to inject a synthetic vulnerability (create a drill).
 */
export type InjectRequest = {
    /**
     * Scenario ID to inject. One of: log4shell, sqli, ssrf, path_traversal, insecure_deserialization, hardcoded_credentials, broken_auth, xss, crypto_weakness, supply_chain — or a custom scenario ID.
     */
    scenario: string;
    /**
     * The component / service to target with the synthetic finding
     */
    target_component: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Optional notes for this drill (not visible to the team being tested)
     */
    notes?: string;
    /**
     * Identifier of the person / system injecting the drill
     */
    injected_by?: (string | null);
};

