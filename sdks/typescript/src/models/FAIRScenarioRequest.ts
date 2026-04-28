/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Input for a single FAIR risk scenario.
 */
export type FAIRScenarioRequest = {
    /**
     * Human-readable scenario label
     */
    scenario_name: string;
    /**
     * Expected threat events per year
     */
    threat_event_frequency_per_year: number;
    /**
     * Probability of successful exploit [0.0, 1.0]
     */
    vulnerability_probability: number;
    /**
     * Minimum primary loss magnitude (USD)
     */
    primary_loss_min_usd: number;
    /**
     * Maximum primary loss magnitude (USD)
     */
    primary_loss_max_usd: number;
    /**
     * Minimum secondary loss (regulatory, reputational) (USD)
     */
    secondary_loss_min_usd?: number;
    /**
     * Maximum secondary loss magnitude (USD)
     */
    secondary_loss_max_usd?: number;
    /**
     * Monte Carlo sample count (100–10000)
     */
    monte_carlo_iterations?: number;
};

