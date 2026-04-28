/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_investment_router__RecordSpendRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Fiscal year (e.g. '2025')
     */
    fiscal_year: string;
    /**
     * Budget category
     */
    category: string;
    /**
     * Amount to record as spent
     */
    amount: number;
};

