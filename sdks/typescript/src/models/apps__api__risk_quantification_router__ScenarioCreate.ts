/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__risk_quantification_router__ScenarioCreate = {
    /**
     * Scenario name
     */
    name: string;
    /**
     * nation_state/cybercriminal/insider/hacktivist/opportunist
     */
    threat_actor?: string;
    /**
     * phishing/supply_chain/zero_day/credential/physical
     */
    attack_vector?: string;
    /**
     * data/infrastructure/application/personnel
     */
    target_asset_type?: string;
    /**
     * Likelihood of occurrence (0-100%)
     */
    likelihood_pct?: number;
    /**
     * Minimum financial loss ($)
     */
    minimum_loss?: number;
    /**
     * Maximum financial loss ($)
     */
    maximum_loss?: number;
};

