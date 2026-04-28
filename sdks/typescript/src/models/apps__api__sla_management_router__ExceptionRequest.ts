/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ExceptionType } from './ExceptionType';
/**
 * Request to submit an SLA exception.
 */
export type apps__api__sla_management_router__ExceptionRequest = {
    finding_id: string;
    exception_type: ExceptionType;
    justification: string;
    requested_by: string;
    expiry_date?: (string | null);
    evidence?: Record<string, any>;
    /**
     * Required for extended_deadline exceptions
     */
    new_deadline?: (string | null);
};

