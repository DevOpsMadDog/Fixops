/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FixCostRequest = {
    /**
     * Finding ID being fixed
     */
    finding_id: string;
    /**
     * Cost of the fix in $
     */
    cost: number;
    /**
     * ISO datetime when fix was deployed
     */
    fixed_at: string;
    /**
     * Optional explicit ALE reduction $. If omitted, inferred from severity.
     */
    ale_reduced?: (number | null);
};

