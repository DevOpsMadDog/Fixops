/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /images/verify-signature — verify image signing.
 */
export type SignatureVerifyRequest = {
    image_ref: string;
    signature_data?: (Record<string, any> | null);
    scheme?: string;
};

