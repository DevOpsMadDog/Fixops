/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * SLA compliance for findings.
 */
export type apps__api__findings_routes__SLAStatus = {
    total_findings: number;
    findings_within_sla: number;
    findings_breaching: number;
    sla_compliance_percent: number;
    by_severity: Record<string, Record<string, number>>;
    findings_at_risk: Array<string>;
};

