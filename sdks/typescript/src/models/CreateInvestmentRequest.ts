/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateInvestmentRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the investment
     */
    investment_name: string;
    /**
     * tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D
     */
    investment_category: string;
    /**
     * Vendor or supplier name
     */
    vendor?: string;
    /**
     * Investment amount
     */
    amount?: number;
    /**
     * USD|EUR|GBP|AUD|CAD
     */
    currency?: string;
    /**
     * ISO start date
     */
    start_date?: string;
    /**
     * ISO end date
     */
    end_date?: string;
};

