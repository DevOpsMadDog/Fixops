/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__crypto_key_management_router__CreateKeyRequest = {
    /**
     * Human-readable key name
     */
    name?: string;
    /**
     * Key algorithm: aes256 | rsa2048 | rsa4096 | ecdsa256 | ed25519
     */
    key_type?: string;
    /**
     * Key purpose: encryption | signing | authentication
     */
    purpose?: string;
    /**
     * Days until the key expires
     */
    expiry_days?: number;
    /**
     * Arbitrary classification tags
     */
    tags?: Array<string>;
};

