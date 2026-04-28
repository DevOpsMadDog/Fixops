/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type BudgetCreate = {
    org_id?: string;
    account_id?: string;
    budget_name: string;
    period?: string;
    limit_usd?: number;
    current_spend_usd?: number;
    alert_threshold_pct?: number;
};

