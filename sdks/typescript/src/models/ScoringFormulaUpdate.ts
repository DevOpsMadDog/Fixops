/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * PUT /api/v1/scoring/formula body.
 */
export type ScoringFormulaUpdate = {
    model_name?: string;
    cvss_weight?: number;
    epss_weight?: number;
    kev_bonus?: number;
    criticality_multiplier?: number;
    exposure_weight?: number;
};

