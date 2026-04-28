/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_budget_router__RecordSpendRequest = {
    /**
     * ID of the budget allocation
     */
    allocation_id: string;
    /**
     * Vendor or payee name
     */
    vendor_name: string;
    /**
     * Spend description
     */
    description?: string;
    /**
     * Transaction amount
     */
    amount: number;
    /**
     * ISO date of transaction
     */
    transaction_date?: (string | null);
};

