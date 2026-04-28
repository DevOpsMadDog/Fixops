/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Regulatory compliance status and exposure.
 */
export type RegulatoryStatusResponse = {
    regulation: string;
    compliance_pct: number;
    max_fine_usd: number;
    estimated_exposure_usd: number;
    gap_count: number;
    remediation_eta_days: number;
    color: string;
    key_gaps: Array<string>;
};

