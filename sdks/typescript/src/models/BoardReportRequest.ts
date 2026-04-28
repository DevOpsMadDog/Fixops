/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FAIRScenarioRequest } from './FAIRScenarioRequest';
/**
 * Request body for board report generation.
 */
export type BoardReportRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * FAIR risk scenarios to simulate
     */
    fair_scenarios?: Array<FAIRScenarioRequest>;
    /**
     * Regulation → compliance % mapping (e.g. {"soc2": 78.5})
     */
    compliance_data?: Record<string, number>;
    /**
     * KPI ID → current value mapping
     */
    kpi_values?: Record<string, number>;
    /**
     * Prior-period KPI values for trend computation
     */
    previous_kpi_values?: (Record<string, number> | null);
    /**
     * Last quarter's risk score for QoQ delta calculation
     */
    prior_quarter_risk_score?: (number | null);
};

