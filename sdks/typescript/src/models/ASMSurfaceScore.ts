/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Overall attack surface score with breakdown.
 */
export type ASMSurfaceScore = {
    org_id: string;
    overall_score: number;
    exposure_score: number;
    vulnerability_score: number;
    configuration_score: number;
    certificate_score: number;
    shadow_it_score: number;
    total_assets: number;
    internet_facing_count: number;
    critical_assets: number;
    shadow_it_count: number;
    unpatched_assets: number;
    expiring_certs: number;
    computed_at?: string;
};

