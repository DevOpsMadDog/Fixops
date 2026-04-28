/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AnalyzeSBOMRequest = {
    /**
     * CycloneDX or SPDX SBOM document
     */
    sbom: Record<string, any>;
    typosquat_threshold?: number;
    min_age_days?: number;
    min_downloads?: number;
};

