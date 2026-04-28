/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /api/v1/toxic-combo-rules body.
 */
export type ToxicComboRule = {
    combo_id: string;
    name: string;
    description?: string;
    severity?: string;
    /**
     * Predicate clauses (attribute + operator + value)
     */
    predicates: Array<Record<string, any>>;
    require_all?: boolean;
};

