/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from POST /evidence/bundles/{bundle_id}/verify.
 *
 * This is the shape the EvidenceBundles UI expects (VerificationResult type).
 */
export type BundleVerificationResult = {
    /**
     * Overall verification result
     */
    valid: boolean;
    /**
     * Whether the content hash matches
     */
    hash_match: boolean;
    /**
     * Whether the cryptographic signature is valid
     */
    signature_valid: boolean;
    /**
     * ISO-8601 timestamp of verification
     */
    timestamp: string;
    /**
     * Certificate chain used for signing
     */
    certificate_chain: Array<string>;
    /**
     * Issuer of the signing certificate
     */
    issuer: string;
};

