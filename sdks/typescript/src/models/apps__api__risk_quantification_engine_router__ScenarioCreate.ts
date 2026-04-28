/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__risk_quantification_engine_router__ScenarioCreate = {
    /**
     * Scenario name
     */
    scenario_name: string;
    /**
     * Asset under threat
     */
    asset_name: string;
    /**
     * Threat actor description
     */
    threat_actor: string;
    /**
     * malware/ransomware/insider/ddos/phishing/supply_chain/physical/natural_disaster/system_failure
     */
    threat_type?: string;
    /**
     * Asset value in $
     */
    asset_value?: number;
    /**
     * Exposure factor 0.0-1.0
     */
    exposure_factor?: number;
    /**
     * Expected occurrences per year
     */
    annual_rate_occurrence?: number;
};

