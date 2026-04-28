/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__algorithmic_router__CVERiskRequest } from './api__algorithmic_router__CVERiskRequest';
/**
 * Request for portfolio-level risk quantification.
 */
export type api__algorithmic_router__PortfolioRiskRequest = {
    /**
     * List of vulnerabilities
     */
    vulnerabilities: Array<api__algorithmic_router__CVERiskRequest>;
    /**
     * Cross-vulnerability correlation
     */
    correlation?: number;
};

