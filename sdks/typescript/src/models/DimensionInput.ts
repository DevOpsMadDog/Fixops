/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DimensionInput = {
    /**
     * One of: vulnerability_hygiene, patch_compliance, security_training, access_control, incident_response, threat_awareness, code_security, configuration_hardening
     */
    dimension: string;
    score: number;
    weight?: number;
    evidence?: string;
};

