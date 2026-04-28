/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A threat model document describing a system under analysis.
 *
 * Contains the system description, data flow, trust boundaries, and
 * references to all identified ThreatEntry records.
 */
export type ThreatModel = {
    id?: string;
    /**
     * Threat model name
     */
    name: string;
    /**
     * Description of the system being modeled
     */
    system_description: string;
    /**
     * Data flow summary (DFD narrative)
     */
    data_flow_description?: string;
    /**
     * Trust boundary labels
     */
    trust_boundaries?: Array<string>;
    /**
     * List of ThreatEntry IDs
     */
    threats?: Array<string>;
    created_at?: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

