/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cyber_threat_modeling_router__ModelCreate = {
    /**
     * Threat model name
     */
    model_name: string;
    /**
     * System being modeled
     */
    system_name: string;
    /**
     * application/infrastructure/cloud/iot/supply_chain/data_flow
     */
    model_type?: string;
    /**
     * Scope description
     */
    scope?: string;
    /**
     * Creator identity
     */
    created_by?: string;
};

