/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Compliance framework report.
 */
export type ComplianceReportResponse = {
    framework: string;
    compliance_percent: number;
    total_controls: number;
    compliant_controls: number;
    gaps: Array<Record<string, any>>;
    evidence_collected: number;
    audit_ready: boolean;
};

