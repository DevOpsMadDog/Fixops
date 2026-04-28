/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for adding a security investment.
 */
export type AddInvestmentRequest = {
    /**
     * Investment name
     */
    name: string;
    /**
     * Category: TOOLS | PERSONNEL | TRAINING | CONSULTING | INSURANCE | INFRASTRUCTURE
     */
    category: string;
    /**
     * One-time or initial cost (USD)
     */
    amount_usd?: number;
    /**
     * Recurring annual cost (USD)
     */
    annual_cost?: number;
    /**
     * Start date YYYY-MM-DD
     */
    start_date?: (string | null);
    /**
     * Investment description
     */
    description?: string;
    /**
     * Optional explicit ID
     */
    investment_id?: (string | null);
};

