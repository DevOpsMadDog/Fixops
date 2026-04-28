/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateSimulationRequest = {
    /**
     * Human-readable simulation name
     */
    name: string;
    /**
     * Optional metadata about target scope
     */
    target_profile?: Record<string, any>;
    /**
     * MITRE ATT&CK tactics to include. Empty = all. Valid: ['initial_access', 'execution', 'persistence', 'privilege_escalation', 'lateral_movement', 'collection', 'exfiltration', 'command_and_control']
     */
    tactics?: Array<string>;
    /**
     * Simulation intensity: ['low', 'medium', 'high']
     */
    intensity?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

