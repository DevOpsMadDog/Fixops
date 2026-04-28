/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordControlRequest = {
    org_id?: string;
    /**
     * Parent benchmark ID
     */
    benchmark_id: string;
    /**
     * Control identifier (e.g. CIS 1.1)
     */
    control_id?: string;
    /**
     * Control title
     */
    title?: string;
    /**
     * Control description
     */
    description?: string;
    /**
     * Result: pass, fail, partial, not_applicable
     */
    result: string;
    /**
     * Severity: critical, high, medium, low
     */
    severity: string;
    /**
     * Remediation guidance
     */
    remediation?: string;
};

