/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Board-level executive risk report.
 */
export type BoardReportResponse = {
    org_id: string;
    report_period: string;
    risk_headline_usd: number;
    risk_trend: string;
    top_5_risks: Array<Record<string, any>>;
    compliance_summary: Record<string, number>;
    kpi_summary: Record<string, any>;
    qoq_delta_pct: number;
    action_items: Array<string>;
    generated_at: string;
};

