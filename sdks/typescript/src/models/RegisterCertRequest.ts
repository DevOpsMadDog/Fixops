/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterCertRequest = {
    org_id?: string;
    /**
     * Asset this certificate belongs to
     */
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
};

