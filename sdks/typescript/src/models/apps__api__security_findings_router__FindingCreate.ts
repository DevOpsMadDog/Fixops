/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_findings_router__FindingCreate = {
    org_id: string;
    title: string;
    finding_type?: string;
    source_tool?: string;
    severity?: string;
    cvss_score?: number;
    asset_id?: string;
    asset_type?: string;
    description?: string;
    remediation?: string;
};

