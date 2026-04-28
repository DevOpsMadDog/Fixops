/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateHuntRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Name of the hunt
     */
    hunt_name: string;
    /**
     * Hunt hypothesis
     */
    hypothesis?: string;
    /**
     * proactive/reactive/scheduled/automated
     */
    hunt_type?: string;
    /**
     * MITRE ATT&CK technique IDs
     */
    technique_ids?: Array<string>;
    /**
     * Analyst running the hunt
     */
    hunter?: string;
};

