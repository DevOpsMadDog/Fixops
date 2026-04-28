/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_modeling_pipeline_router__CreateModelRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the threat model
     */
    model_name: string;
    /**
     * Description of the system being modeled
     */
    system_description?: string;
    /**
     * STRIDE|PASTA|VAST|attack-tree|OCTAVE|custom
     */
    methodology?: string;
    /**
     * Creator username or ID
     */
    created_by?: string;
};

