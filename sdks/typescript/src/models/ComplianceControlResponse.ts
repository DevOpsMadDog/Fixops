/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a compliance control.
 */
export type ComplianceControlResponse = {
    control_id: string;
    framework: string;
    title: string;
    description: string;
    requirements: Array<string>;
    evidence_types: Array<string>;
    automation_level: string;
};

