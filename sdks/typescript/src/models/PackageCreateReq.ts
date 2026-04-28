/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PackageCreateReq = {
    org_id: string;
    package_name: string;
    ecosystem?: string;
    version?: (string | null);
    source_url?: (string | null);
    risk_score?: number;
    attack_type?: string;
    last_scanned?: (string | null);
};

