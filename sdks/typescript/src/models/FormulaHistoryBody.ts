/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FormulaHistoryBody = {
    formula_version: string;
    change_summary?: string;
    approver?: string;
    /**
     * ISO-8601 approval timestamp; defaults to now().
     */
    approved_at?: (string | null);
};

