/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for Bayesian probability update.
 */
export type BayesianUpdateRequest = {
    /**
     * Component definitions with optional observed states
     */
    components: Array<Record<string, any>>;
    /**
     * Bayesian network definition with nodes and CPTs
     */
    network: Record<string, any>;
};

