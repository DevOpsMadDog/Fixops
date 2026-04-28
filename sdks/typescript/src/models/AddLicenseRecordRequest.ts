/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddLicenseRecordRequest = {
    org_id?: string;
    package_name: string;
    package_version?: string;
    license_type?: string;
    license_risk?: string;
    is_oss?: boolean;
    has_vulnerabilities?: boolean;
    vuln_count?: number;
    approved?: boolean;
};

