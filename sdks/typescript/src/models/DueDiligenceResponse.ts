/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * M&A due diligence security report.
 */
export type DueDiligenceResponse = {
    org_id: string;
    security_debt_usd: number;
    compliance_readiness_pct: number;
    critical_vuln_count: number;
    high_vuln_count: number;
    time_to_remediation_days: number;
    insurance_premium_impact_usd: number;
    risk_rating: string;
    findings_summary: Array<string>;
    computed_at: string;
};

