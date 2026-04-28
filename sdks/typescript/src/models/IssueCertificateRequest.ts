/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IssueCertificateRequest = {
    /**
     * Common name (CN) for the certificate
     */
    common_name: string;
    /**
     * ISO expiry timestamp
     */
    expires_at: string;
    /**
     * Serial number
     */
    serial_number?: (string | null);
    /**
     * Issuing CA
     */
    issuer?: (string | null);
    /**
     * SANs
     */
    subject_alt_names?: (Array<string> | null);
    /**
     * RSA | ECDSA | DSA
     */
    key_algorithm?: (string | null);
    /**
     * Key size in bits
     */
    key_size?: (number | null);
    /**
     * root_ca | intermediate_ca | server | client | code_signing | email
     */
    cert_type?: (string | null);
    /**
     * initial status
     */
    status?: (string | null);
    /**
     * ISO issued timestamp
     */
    issued_at?: (string | null);
    /**
     * Auto-renew flag
     */
    auto_renew?: (boolean | null);
    /**
     * Issuing actor
     */
    actor?: (string | null);
};

