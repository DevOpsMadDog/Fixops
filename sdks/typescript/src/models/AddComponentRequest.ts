/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddComponentRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the component
     */
    component_name: string;
    /**
     * process|datastore|external-entity|data-flow|trust-boundary
     */
    component_type: string;
    /**
     * Trust boundary this component belongs to
     */
    trust_boundary?: string;
    /**
     * List of connected component names
     */
    data_flows?: Array<string>;
};

