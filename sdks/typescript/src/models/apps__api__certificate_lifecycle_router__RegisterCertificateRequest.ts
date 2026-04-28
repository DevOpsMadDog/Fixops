/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__certificate_lifecycle_router__RegisterCertificateRequest = {
    /**
     * Primary domain / subject CN
     */
    domain?: string;
    /**
     * Certificate Authority name
     */
    issuer?: string;
    /**
     * Certificate type: ssl | code_signing | client | ca
     */
    cert_type?: string;
    /**
     * Expiry timestamp in ISO 8601 format (e.g. 2027-01-01T00:00:00+00:00)
     */
    expiry_date?: string;
    /**
     * Subject Alternative Names
     */
    san_list?: Array<string>;
    /**
     * Whether to auto-renew before expiry
     */
    auto_renew?: boolean;
};

