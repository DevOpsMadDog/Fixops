/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_security_router__RegisterCertificateRequest = {
    /**
     * Hostname
     */
    host: string;
    /**
     * TLS port
     */
    port?: number;
    /**
     * Certificate CN
     */
    subject_cn: string;
    /**
     * Certificate issuer
     */
    issuer: string;
    /**
     * Certificate validity start
     */
    not_before: string;
    /**
     * Certificate expiry
     */
    not_after: string;
    /**
     * TLS protocol version negotiated
     */
    protocol_version?: string;
    /**
     * Cipher suite in use
     */
    cipher_suite?: string;
    /**
     * Whether cert appears in CT logs
     */
    ct_logged?: boolean;
    /**
     * SAN domain list
     */
    san_domains?: Array<string>;
    org_id?: string;
};

