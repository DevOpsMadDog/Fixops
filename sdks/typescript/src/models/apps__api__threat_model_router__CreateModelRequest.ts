/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_model_router__CreateModelRequest = {
    /**
     * Threat model name
     */
    name: string;
    /**
     * Description of system being modeled
     */
    system_description: string;
    /**
     * Data flow narrative (DFD summary)
     */
    data_flow_description?: string;
    /**
     * Trust boundary labels
     */
    trust_boundaries?: Array<string>;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

