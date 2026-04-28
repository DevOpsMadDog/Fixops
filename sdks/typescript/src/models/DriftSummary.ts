/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Aggregated drift summary for an organisation.
 */
export type DriftSummary = {
    total_resources: number;
    compliant: number;
    drifted: number;
    compliance_rate: number;
    by_severity: Record<string, number>;
    by_provider: Record<string, number>;
    top_drifts: Array<Record<string, any>>;
};

