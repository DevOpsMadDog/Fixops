/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * New weights for one or more factors.
 */
export type WeightsUpdateRequest = {
    /**
     * Factor → weight mapping. Known factors: cvss_score, epss_score, asset_criticality, exposure_level, exploit_available, age_days, has_patch, in_attack_path
     */
    weights: Record<string, number>;
};

