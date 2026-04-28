/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for counterfactual what-if analysis.
 */
export type api__causal_router__CounterfactualRequest = {
    /**
     * Map of SecurityFactor names to their boolean state
     */
    evidence?: Record<string, boolean>;
    /**
     * SecurityFactor to intervene on
     */
    intervention_factor: string;
    intervention_value?: boolean;
    /**
     * SecurityFactor to measure outcome on
     */
    outcome_factor?: string;
};

