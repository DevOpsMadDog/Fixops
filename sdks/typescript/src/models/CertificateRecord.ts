/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * TLS certificate tracked per asset.
 */
export type CertificateRecord = {
    id?: string;
    org_id?: string;
    asset_id: string;
    asset_name: string;
    subject: string;
    issuer: string;
    valid_from: string;
    valid_to: string;
    days_until_expiry: number;
    san_domains?: Array<string>;
    is_expired?: boolean;
    is_self_signed?: boolean;
    tls_version?: string;
    cipher_suite?: string;
    grade?: string;
    checked_at?: string;
};

