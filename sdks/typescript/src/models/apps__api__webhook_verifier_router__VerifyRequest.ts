/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Payload for manual (non-auto-detect) verification requests.
 */
export type apps__api__webhook_verifier_router__VerifyRequest = {
    /**
     * Raw webhook payload (UTF-8 string or hex-encoded bytes)
     */
    payload: string;
    /**
     * Signature header value sent by the provider
     */
    signature: string;
    /**
     * Shared secret configured for this integration
     */
    secret: string;
    /**
     * Timestamp header value (required for Slack / Stripe)
     */
    timestamp?: (string | null);
    /**
     * HMAC algorithm for CUSTOM provider (sha256, sha1, sha512, md5)
     */
    algorithm?: (string | null);
    /**
     * Source IP for audit log
     */
    ip_address?: (string | null);
};

