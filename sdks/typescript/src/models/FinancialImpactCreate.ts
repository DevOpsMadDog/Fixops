/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FinancialImpactCreate = {
    /**
     * Type of incident
     */
    incident_type: string;
    direct_cost?: number;
    regulatory_fines?: number;
    remediation_cost?: number;
    business_disruption_cost?: number;
    reputational_cost?: number;
    /**
     * ISO date string (defaults to now)
     */
    incident_date?: (string | null);
    /**
     * Fiscal year (defaults to current year)
     */
    fiscal_year?: (number | null);
};

