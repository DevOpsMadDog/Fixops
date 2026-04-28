/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__postfix_verify_router__VerifyFixRequest } from './api__postfix_verify_router__VerifyFixRequest';
/**
 * Request body for POST /api/v1/verify/bulk.
 *
 * Up to 20 fix verifications in a single request.
 */
export type BulkVerifyRequest = {
    /**
     * List of fix verification requests (max 20)
     */
    fixes: Array<api__postfix_verify_router__VerifyFixRequest>;
    /**
     * Stop on first failed verification
     */
    fail_fast?: boolean;
};

