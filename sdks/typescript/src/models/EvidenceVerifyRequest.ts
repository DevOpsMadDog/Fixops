/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for the legacy POST /evidence/verify endpoint.
 */
export type EvidenceVerifyRequest = {
    /**
     * The evidence bundle ID to verify
     */
    bundle_id: string;
    /**
     * Base64-encoded RSA signature (optional, will be read from manifest if not provided)
     */
    signature?: (string | null);
    /**
     * Public key fingerprint (optional, will be read from manifest if not provided)
     */
    fingerprint?: (string | null);
};

