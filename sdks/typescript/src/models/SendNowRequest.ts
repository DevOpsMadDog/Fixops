/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SendNowRequest = {
    /**
     * One of: ['executive_summary', 'vulnerability_digest', 'compliance_status', 'threat_intel_brief', 'kpi_scorecard']
     */
    report_type: string;
    recipients?: Array<string>;
    channels?: Array<string>;
    format?: string;
    filters?: Record<string, any>;
    org_id?: string;
};

