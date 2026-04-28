/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Compliance mapping result.
 */
export type ComplianceMappingResponse = {
    framework: string;
    controls_mapped?: number;
    controls_affected?: Array<Record<string, any>>;
    gap_score?: (number | null);
    remediation_priority?: Array<string>;
    status?: (string | null);
    message?: (string | null);
};

