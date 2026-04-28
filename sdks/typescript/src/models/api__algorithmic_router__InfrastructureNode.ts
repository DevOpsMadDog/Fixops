/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Infrastructure node for attack graph.
 */
export type api__algorithmic_router__InfrastructureNode = {
    id: string;
    /**
     * Node type: compute, storage, network, identity, service, etc.
     */
    type?: string;
    properties?: Record<string, any>;
    risk_score?: number;
};

