/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RiskCategory } from './RiskCategory';
export type SetAppetiteRequest = {
    category: RiskCategory;
    /**
     * Maximum acceptable residual risk score
     */
    appetite_score: number;
    /**
     * Escalation threshold
     */
    tolerance_score: number;
    description?: string;
    updated_by?: string;
    org_id?: string;
};

