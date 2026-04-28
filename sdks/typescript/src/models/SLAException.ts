/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ExceptionStatus } from './ExceptionStatus';
import type { ExceptionType } from './ExceptionType';
/**
 * Exception request for an SLA assignment.
 */
export type SLAException = {
    id?: string;
    finding_id: string;
    org_id: string;
    exception_type: ExceptionType;
    justification: string;
    requested_by: string;
    approved_by?: (string | null);
    status?: ExceptionStatus;
    expiry_date?: (string | null);
    evidence?: Record<string, any>;
    new_deadline?: (string | null);
    created_at?: string;
    updated_at?: string;
};

