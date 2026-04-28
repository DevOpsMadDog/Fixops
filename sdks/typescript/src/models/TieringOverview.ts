/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Summary of vendor tiering across the registry.
 */
export type TieringOverview = {
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    untiered_count?: number;
    tier_breakdown?: Record<string, Array<string>>;
    assessment_requirements?: Record<string, Record<string, any>>;
};

