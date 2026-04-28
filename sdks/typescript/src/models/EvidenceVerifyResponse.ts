/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from the legacy POST /evidence/verify endpoint.
 */
export type EvidenceVerifyResponse = {
    bundle_id: string;
    verified: boolean;
    fingerprint?: (string | null);
    signed_at?: (string | null);
    signature_algorithm?: (string | null);
    error?: (string | null);
};

