/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TraceRequest } from './TraceRequest';
/**
 * Batch trace request for multiple vulnerabilities.
 */
export type BatchTraceRequest = {
    /**
     * List of vulnerabilities to trace
     */
    vulnerabilities: Array<TraceRequest>;
};

