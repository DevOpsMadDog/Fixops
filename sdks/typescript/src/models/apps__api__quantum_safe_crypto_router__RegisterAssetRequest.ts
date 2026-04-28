/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__quantum_safe_crypto_router__RegisterAssetRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Name of the cryptographic asset
     */
    asset_name: string;
    /**
     * Type: tls_certificate, vpn, signing_key, encryption_key, code_signing, database_encryption, api_key, ssh_key
     */
    asset_type: string;
    /**
     * Current algorithm: rsa, ecdsa, dh, aes, 3des, sha1, sha256, sha384, sha512
     */
    current_algorithm: string;
    /**
     * Key size in bits
     */
    key_size?: number;
    /**
     * Risk level: critical, high, medium, low
     */
    risk_level?: string;
    /**
     * Migration status: not_started, planned, in_progress, completed, exempt
     */
    migration_status?: string;
    /**
     * ISO 8601 discovery timestamp
     */
    discovered_at?: (string | null);
};

