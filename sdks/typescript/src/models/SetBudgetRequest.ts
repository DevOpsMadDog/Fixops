/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SetBudgetRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Fiscal year (e.g. '2025')
     */
    fiscal_year: string;
    /**
     * tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D
     */
    category: string;
    /**
     * Allocated budget amount
     */
    allocated: number;
    /**
     * USD|EUR|GBP|AUD|CAD
     */
    currency?: string;
};

