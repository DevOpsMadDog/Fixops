/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateProgramRequest = {
    /**
     * Program name (e.g. 'ALDECI Public VDP')
     */
    name: string;
    /**
     * Program description and goals
     */
    description?: string;
    /**
     * Monthly reward budget cap (USD)
     */
    monthly_budget?: number;
    /**
     * Safe harbor policy text
     */
    safe_harbor?: string;
    /**
     * Full legal terms and conditions
     */
    legal_terms?: string;
    /**
     * In-scope assets
     */
    in_scope?: Array<string>;
    /**
     * Out-of-scope assets
     */
    out_of_scope?: Array<string>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

