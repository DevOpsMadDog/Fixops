/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for Monte Carlo risk quantification.
 */
export type api__algorithmic_router__MonteCarloRequest = {
    /**
     * Min annual threat events
     */
    threat_event_frequency_min?: number;
    /**
     * Most likely annual threat events
     */
    threat_event_frequency_mode?: number;
    /**
     * Max annual threat events
     */
    threat_event_frequency_max?: number;
    /**
     * Min probability of successful exploit
     */
    vulnerability_probability_min?: number;
    /**
     * Most likely probability
     */
    vulnerability_probability_mode?: number;
    /**
     * Max probability
     */
    vulnerability_probability_max?: number;
    /**
     * Minimum loss in dollars
     */
    loss_magnitude_min?: number;
    /**
     * Most likely loss
     */
    loss_magnitude_mode?: number;
    /**
     * Maximum loss
     */
    loss_magnitude_max?: number;
    /**
     * Number of simulations
     */
    iterations?: number;
    /**
     * Confidence level for intervals
     */
    confidence_level?: number;
};

