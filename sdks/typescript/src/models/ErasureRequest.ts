/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ErasureStatus } from './ErasureStatus';
/**
 * GDPR right-to-erasure request for a data subject.
 */
export type ErasureRequest = {
    id?: string;
    subject_email: string;
    requested_at?: string;
    completed_at?: (string | null);
    status?: ErasureStatus;
    categories_erased?: Array<string>;
    org_id?: string;
};

