/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for creating a risk scenario.
 */
export type apps__api__risk_quantifier_router__CreateScenarioRequest = {
    /**
     * Human-readable scenario name
     */
    name: string;
    /**
     * Description of the threat event
     */
    threat_event: string;
    /**
     * Asset value in USD
     */
    asset_value_usd: number;
    /**
     * Minimum loss estimate (USD)
     */
    loss_magnitude_low: number;
    /**
     * Maximum loss estimate (USD)
     */
    loss_magnitude_high: number;
    /**
     * Min annual probability
     */
    probability_low: number;
    /**
     * Max annual probability
     */
    probability_high: number;
    /**
     * Optional ALE override
     */
    annual_loss_expectancy?: (number | null);
    /**
     * Optional explicit scenario ID
     */
    scenario_id?: (string | null);
};

