/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FixVerifyRequest } from './FixVerifyRequest';
/**
 * Batch verification request.
 */
export type BatchFixVerifyRequest = {
    /**
     * Up to 50 fixes to verify
     */
    fixes: Array<FixVerifyRequest>;
};

