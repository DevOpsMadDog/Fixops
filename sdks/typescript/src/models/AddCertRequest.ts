/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddCertRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Primary domain
     */
    domain: string;
    /**
     * Certificate issuer CN/O
     */
    issuer?: string;
    /**
     * Serial number
     */
    serial?: string;
    /**
     * Validity start (ISO-8601)
     */
    not_before?: string;
    /**
     * Validity end (ISO-8601)
     */
    not_after?: string;
    /**
     * Signature algorithm (e.g. sha256WithRSAEncryption)
     */
    algorithm?: string;
    /**
     * Public key size in bits
     */
    key_size?: number;
    /**
     * Subject Alternative Names
     */
    san_list?: Array<string>;
    /**
     * Wildcard certificate flag
     */
    wildcard?: boolean;
};

