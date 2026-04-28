/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TLSCertificate = {
    id?: string;
    org_id: string;
    host: string;
    port?: number;
    subject_cn: string;
    issuer: string;
    not_before: string;
    not_after: string;
    protocol_version?: string;
    cipher_suite?: string;
    ct_logged?: boolean;
    san_domains?: Array<string>;
    observed_at?: string;
};

