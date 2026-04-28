/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAllocationRequest = {
    /**
     * Fiscal year (positive integer)
     */
    fiscal_year: number;
    /**
     * tools|personnel|training|consulting|infrastructure|compliance|incident_response
     */
    category: string;
    /**
     * Budget amount in currency
     */
    allocated_amount: number;
    /**
     * Currency code
     */
    currency?: string;
    /**
     * Optional notes
     */
    notes?: string;
};

