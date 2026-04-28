/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_surface_engine_router__ExposureCreate = {
    exposure_type?: string;
    severity?: string;
    title: string;
    description?: string;
    evidence?: string;
    cvss_score?: number;
    remediation?: string;
    first_detected?: (string | null);
    last_seen?: (string | null);
};

