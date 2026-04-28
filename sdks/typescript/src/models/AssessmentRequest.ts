/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssessmentRequest = {
    org_id: string;
    target: string;
    cve_ids: Array<string>;
    scan_type?: string;
    compliance_frameworks?: (Array<string> | null);
};

