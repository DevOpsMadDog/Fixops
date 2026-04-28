/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__monte_carlo_router__CVERiskRequest } from './api__monte_carlo_router__CVERiskRequest';
/**
 * Portfolio-level risk simulation across multiple CVEs.
 */
export type api__monte_carlo_router__PortfolioRiskRequest = {
    cves: Array<api__monte_carlo_router__CVERiskRequest>;
    /**
     * Assumed correlation between CVE losses (0=independent, 1=fully correlated)
     */
    correlation_factor?: number;
};

