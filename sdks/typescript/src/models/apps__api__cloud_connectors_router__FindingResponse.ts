/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_connectors_router__FindingResponse = {
    finding_id: string;
    provider: string;
    source_service: string;
    title: string;
    description: string;
    severity: string;
    resource_id?: (string | null);
    resource_type?: (string | null);
    region?: (string | null);
    account_id?: (string | null);
    remediation?: (string | null);
    compliance_standards?: Array<string>;
};

