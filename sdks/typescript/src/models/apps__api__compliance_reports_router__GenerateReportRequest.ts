/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for generating a compliance report.
 */
export type apps__api__compliance_reports_router__GenerateReportRequest = {
    /**
     * One of: SOC2, PCI, HIPAA, ISO27001, NIST, GDPR, CIS
     */
    framework: string;
    title?: (string | null);
    findings_context?: (Record<string, any> | null);
};

